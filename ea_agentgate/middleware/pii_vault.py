"""PII vault middleware for redaction and permission-aware restoration."""

from __future__ import annotations

import asyncio
import copy
import logging
import os
from typing import Any, TYPE_CHECKING, TypedDict

from ..api_client import ApiError, DashboardClient
from .base import Middleware, MiddlewareContext
from .pii_vault_detector import PIIDetector, PIIPatterns, warmup
from .pii_vault_manager import PlaceholderManager
from .pii_vault_models import PIIEntity, RedactionResult

if TYPE_CHECKING:
    from ..backends import PIIVaultBackend
    from ..providers.base import LLMProvider

logger = logging.getLogger(__name__)


class PIIVaultError(RuntimeError):
    """Base error raised for server-scoped PII middleware failures."""


class PIIRestoreAuthorizationError(PIIVaultError):
    """Raised when restore is denied by server-side authorization checks."""


class PIIRestoreIntegrityError(PIIVaultError):
    """Raised when restore fails due to token integrity violations."""


class PIIRestoreUnknownTokenError(PIIVaultError):
    """Raised when restore fails because unmapped placeholder tokens were encountered."""


class PIIRuntimeApiError(PIIVaultError):
    """Raised for generic server-scoped PII API failures."""


class PIIVaultConfig(TypedDict, total=False):
    """Configuration controlling PII redaction and restore behavior."""

    redact_inputs: bool
    rehydrate_outputs: bool
    pii_types: list[str] | None
    placeholder_format: str
    store_ttl: float | None
    use_llm_detection: bool
    use_server_api: bool | None
    fail_closed: bool


class PIIVaultScope(TypedDict, total=False):
    """Runtime scoping information for server-backed PII operations."""

    pii_session_id: str | None
    channel_id: str | None
    conversation_id: str | None


_PII_VAULT_CONFIG_DEFAULTS: PIIVaultConfig = {
    "redact_inputs": True,
    "rehydrate_outputs": True,
    "pii_types": None,
    "placeholder_format": "<{type}_{id}>",
    "store_ttl": 3600.0,
    "use_llm_detection": False,
    "use_server_api": None,
    "fail_closed": True,
}
_PII_VAULT_SCOPE_DEFAULTS: PIIVaultScope = {
    "pii_session_id": None,
    "channel_id": None,
    "conversation_id": None,
}


def _merge_typed_settings(
    defaults: dict[str, Any],
    source: dict[str, Any] | None,
) -> dict[str, Any]:
    """Return a shallow copy of defaults updated with provided typed settings."""
    resolved = dict(defaults)
    if source:
        for key in defaults:
            if key in source:
                resolved[key] = source[key]
    return resolved


def _parse_pii_vault_settings(
    config: PIIVaultConfig | None,
    scope: PIIVaultScope | None,
    legacy_kwargs: dict[str, Any],
) -> tuple[PIIVaultConfig, PIIVaultScope]:
    """Merge legacy PII vault kwargs into structured config and scope values."""
    resolved_config = _merge_typed_settings(_PII_VAULT_CONFIG_DEFAULTS, config)
    resolved_scope = _merge_typed_settings(_PII_VAULT_SCOPE_DEFAULTS, scope)

    config_keys = set(_PII_VAULT_CONFIG_DEFAULTS)
    scope_keys = set(_PII_VAULT_SCOPE_DEFAULTS)
    unknown_keys = set(legacy_kwargs) - config_keys - scope_keys
    if unknown_keys:
        names = ", ".join(sorted(unknown_keys))
        raise TypeError(f"Unsupported PIIVault option(s): {names}")

    for key in config_keys:
        if key in legacy_kwargs:
            resolved_config[key] = legacy_kwargs[key]
    for key in scope_keys:
        if key in legacy_kwargs:
            resolved_scope[key] = legacy_kwargs[key]
    return resolved_config, resolved_scope


class PIIVault(Middleware):
    """Middleware that redacts inbound text and restores outbound text."""

    def __init__(
        self,
        backend: "PIIVaultBackend | None" = None,
        detector: PIIDetector | None = None,
        redact_inputs: bool = True,
        *,
        config: PIIVaultConfig | None = None,
        scope: PIIVaultScope | None = None,
        llm_provider: "LLMProvider | None" = None,
        api_client: DashboardClient | None = None,
        **legacy_kwargs: Any,
    ):
        legacy_kwargs.setdefault("redact_inputs", redact_inputs)
        self._config, self._scope = _parse_pii_vault_settings(config, scope, legacy_kwargs)
        resolved_use_server_api = self._config["use_server_api"]
        if resolved_use_server_api is None:
            resolved_use_server_api = (
                os.getenv("AGENTGATE_SDK_PROFILE", "").strip().lower() == "enterprise"
            )
        self._config["use_server_api"] = resolved_use_server_api

        if not resolved_use_server_api and backend is None:
            raise ValueError("backend is required when use_server_api=False")

        super().__init__()
        self.backend = backend
        self._api_client = api_client
        self.detector = detector or PIIDetector(
            pii_types=self.pii_types,
            use_regex=True,
            use_llm=self._config["use_llm_detection"],
            provider=llm_provider,
        )

    @property
    def redact_inputs(self) -> bool:
        """Return whether input payloads should be redacted."""
        return self._config["redact_inputs"]

    @property
    def rehydrate_outputs(self) -> bool:
        """Return whether output payloads should be restored."""
        return self._config["rehydrate_outputs"]

    @property
    def pii_types(self) -> list[str] | None:
        """Return the configured PII types filter."""
        return self._config["pii_types"]

    @property
    def placeholder_format(self) -> str:
        """Return the placeholder token format."""
        return self._config["placeholder_format"]

    @property
    def store_ttl(self) -> float | None:
        """Return the local backend storage TTL."""
        return self._config["store_ttl"]

    @property
    def use_server_api(self) -> bool:
        """Return whether server-backed PII APIs are enabled."""
        return bool(self._config["use_server_api"])

    @property
    def fail_closed(self) -> bool:
        """Return whether server-backed PII failures should block execution."""
        return self._config["fail_closed"]

    @property
    def pii_session_id(self) -> str | None:
        """Return the default scoped PII session identifier."""
        return self._scope["pii_session_id"]

    @property
    def channel_id(self) -> str | None:
        """Return the default scoped channel identifier."""
        return self._scope["channel_id"]

    @property
    def conversation_id(self) -> str | None:
        """Return the default scoped conversation identifier."""
        return self._scope["conversation_id"]

    def before(self, ctx: MiddlewareContext) -> None:
        """Redact PII from tool inputs before execution."""
        if not self.redact_inputs:
            return

        ctx.metadata["pii_original_inputs"] = copy.deepcopy(ctx.inputs)

        if self.use_server_api:
            redacted_inputs, redaction_log = self.redact_payload(
                ctx.inputs,
                session_id=ctx.session_id,
                agent_id=ctx.agent_id,
                channel_id=str(ctx.metadata.get("channel_id", "")) or None,
                conversation_id=str(ctx.metadata.get("conversation_id", "")) or None,
            )
            ctx.inputs = redacted_inputs
            ctx.metadata["pii_redacted"] = redaction_log
            return

        placeholder_mgr = PlaceholderManager(self.placeholder_format)
        redacted_inputs, redaction_log = self._redact_dict(
            ctx.inputs,
            placeholder_mgr,
            ctx.session_id,
        )
        ctx.inputs = redacted_inputs
        ctx.metadata["pii_redacted"] = redaction_log
        ctx.metadata["_pii_placeholder_mgr"] = placeholder_mgr

    def after(
        self,
        ctx: MiddlewareContext,
        result: Any,
        error: Exception | None,
    ) -> None:
        """Restore PII placeholders in tool output after execution."""
        if not self.rehydrate_outputs or error is not None:
            return

        if self.use_server_api:
            restored_result, rehydration_log = self.restore_payload(
                result,
                session_id=ctx.session_id,
                agent_id=ctx.agent_id,
                channel_id=str(ctx.metadata.get("channel_id", "")) or None,
                conversation_id=str(ctx.metadata.get("conversation_id", "")) or None,
            )
        else:
            if self.backend is None:
                return
            mappings = self.backend.get_all_mappings(ctx.session_id)
            if not mappings:
                return
            restored_result, rehydration_log = self._rehydrate_value(result, mappings)

        ctx.metadata["pii_rehydrated"] = rehydration_log
        if rehydration_log:
            ctx.metadata["pii_rehydrated_result"] = restored_result
            ctx.metadata["result_override"] = restored_result

    async def abefore(self, ctx: MiddlewareContext) -> None:
        """Async redact PII from tool inputs."""
        if not self.redact_inputs:
            return

        ctx.metadata["pii_original_inputs"] = copy.deepcopy(ctx.inputs)

        if self.use_server_api:
            redacted_inputs, redaction_log = await asyncio.to_thread(
                self.redact_payload,
                ctx.inputs,
                ctx.session_id,
                ctx.agent_id,
                channel_id=str(ctx.metadata.get("channel_id", "")) or None,
                conversation_id=str(ctx.metadata.get("conversation_id", "")) or None,
            )
            ctx.inputs = redacted_inputs
            ctx.metadata["pii_redacted"] = redaction_log
            return

        placeholder_mgr = PlaceholderManager(self.placeholder_format)
        redacted_inputs, redaction_log = await self._aredact_dict(
            ctx.inputs,
            placeholder_mgr,
            ctx.session_id,
        )
        ctx.inputs = redacted_inputs
        ctx.metadata["pii_redacted"] = redaction_log
        ctx.metadata["_pii_placeholder_mgr"] = placeholder_mgr

    async def aafter(
        self,
        ctx: MiddlewareContext,
        result: Any,
        error: Exception | None,
    ) -> None:
        """Async restore PII placeholders in tool output."""
        if not self.rehydrate_outputs or error is not None:
            return

        if self.use_server_api:
            restored_result, rehydration_log = await asyncio.to_thread(
                self.restore_payload,
                result,
                ctx.session_id,
                ctx.agent_id,
                channel_id=str(ctx.metadata.get("channel_id", "")) or None,
                conversation_id=str(ctx.metadata.get("conversation_id", "")) or None,
            )
        else:
            self.after(ctx, result, error)
            return

        ctx.metadata["pii_rehydrated"] = rehydration_log
        if rehydration_log:
            ctx.metadata["pii_rehydrated_result"] = restored_result
            ctx.metadata["result_override"] = restored_result

    def is_async_native(self) -> bool:
        """Return whether middleware provides native async behavior."""
        return self.detector.use_llm or self.use_server_api

    def redact_payload(
        self,
        payload: Any,
        session_id: str | None = None,
        agent_id: str | None = None,
        *,
        channel_id: str | None = None,
        conversation_id: str | None = None,
    ) -> tuple[Any, list[dict[str, Any]]]:
        """Redact all strings in a nested payload."""
        resolved_session = self._resolve_session_id(session_id)
        if not self.use_server_api:
            placeholder_mgr = PlaceholderManager(self.placeholder_format)
            return self._redact_value(payload, placeholder_mgr, resolved_session)
        return self._redact_server_value(
            payload,
            session_id=resolved_session,
            headers=self._build_headers(
                agent_id=agent_id,
                channel_id=channel_id,
                conversation_id=conversation_id,
            ),
        )

    def restore_payload(
        self,
        payload: Any,
        session_id: str | None = None,
        agent_id: str | None = None,
        *,
        channel_id: str | None = None,
        conversation_id: str | None = None,
    ) -> tuple[Any, list[dict[str, Any]]]:
        """Restore all placeholders in a nested payload."""
        resolved_session = self._resolve_session_id(session_id)
        if not self.use_server_api:
            if self.backend is None:
                return payload, []
            mappings = self.backend.get_all_mappings(resolved_session)
            if not mappings:
                return payload, []
            return self._rehydrate_value(payload, mappings)
        return self._restore_server_value(
            payload,
            session_id=resolved_session,
            headers=self._build_headers(
                agent_id=agent_id,
                channel_id=channel_id,
                conversation_id=conversation_id,
            ),
        )

    def _resolve_session_id(self, session_id: str | None) -> str | None:
        """Resolve session id from call context or middleware defaults."""
        resolved = session_id or self.pii_session_id
        if resolved:
            return resolved
        if self.use_server_api and self.fail_closed:
            raise RuntimeError(
                "PII middleware in server mode requires a session_id "
                "(ctx.session_id or pii_session_id)"
            )
        if self.use_server_api:
            logger.warning("PII session_id missing; skipping scoped PII transformation")
        return None

    def _build_headers(
        self,
        *,
        agent_id: str | None,
        channel_id: str | None,
        conversation_id: str | None,
    ) -> dict[str, str]:
        headers: dict[str, str] = {}
        final_agent_id = agent_id
        final_channel_id = channel_id or self.channel_id
        final_conversation_id = conversation_id or self.conversation_id

        if self.use_server_api and self.fail_closed and not final_agent_id:
            raise PIIRuntimeApiError(
                "PII middleware in server mode requires agent_id for scoped restore/redact calls"
            )

        if final_agent_id:
            headers["x-agent-id"] = final_agent_id
        if final_channel_id:
            headers["x-channel-id"] = final_channel_id
        if final_conversation_id:
            headers["x-conversation-id"] = final_conversation_id
        return headers

    def _require_api_client(self) -> DashboardClient:
        if self._api_client is None:
            self._api_client = DashboardClient()
        return self._api_client

    def _handle_api_error(self, *, operation: str, exc: ApiError) -> None:
        message = f"PII {operation} failed (status={exc.status}): {exc.message}"
        detail_payload = exc.detail if isinstance(exc.detail, dict) else {}
        detail_body = detail_payload.get("detail")
        if isinstance(detail_body, dict):
            detail_payload = detail_body
        detail_error = str(detail_payload.get("error", "")).strip().lower()

        if operation == "restore" and exc.status == 403 and self.fail_closed:
            raise PIIRestoreAuthorizationError(message) from exc
        if (
            operation == "restore"
            and exc.status == 409
            and detail_error == "token_integrity_failure"
            and self.fail_closed
        ):
            raise PIIRestoreIntegrityError(message) from exc
        if (
            operation == "restore"
            and exc.status == 409
            and detail_error == "unknown_token"
            and self.fail_closed
        ):
            raise PIIRestoreUnknownTokenError(message) from exc

        if self.fail_closed:
            raise PIIRuntimeApiError(message) from exc
        logger.warning("%s; fail-open active", message)

    def _redact_server_text(
        self,
        text: str,
        *,
        session_id: str | None,
        headers: dict[str, str],
    ) -> tuple[str, list[dict[str, Any]]]:
        if session_id is None:
            return text, []
        try:
            response = self._require_api_client().post(
                "/api/pii/redact",
                body={"session_id": session_id, "text": text},
                headers=headers,
            )
        except ApiError as exc:
            self._handle_api_error(operation="redact", exc=exc)
            return text, []

        redacted_text = str(response.get("redacted_text", text))
        mappings = response.get("mappings", [])
        if isinstance(mappings, list):
            return redacted_text, mappings
        return redacted_text, []

    def _restore_server_text(
        self,
        text: str,
        *,
        session_id: str | None,
        headers: dict[str, str],
    ) -> tuple[str, list[dict[str, Any]]]:
        if session_id is None:
            return text, []
        try:
            response = self._require_api_client().post(
                "/api/pii/restore",
                body={"session_id": session_id, "text": text},
                headers=headers,
            )
        except ApiError as exc:
            self._handle_api_error(operation="restore", exc=exc)
            return text, []

        restored_text = str(response.get("restored_text", text))
        restorations = response.get("restorations", [])
        if isinstance(restorations, list):
            return restored_text, restorations
        return restored_text, []

    def _redact_server_value(
        self,
        value: Any,
        *,
        session_id: str | None,
        headers: dict[str, str],
    ) -> tuple[Any, list[dict[str, Any]]]:
        if isinstance(value, str):
            return self._redact_server_text(value, session_id=session_id, headers=headers)
        if isinstance(value, dict):
            redacted: dict[str, Any] = {}
            log: list[dict[str, Any]] = []
            for key, inner in value.items():
                transformed, events = self._redact_server_value(
                    inner,
                    session_id=session_id,
                    headers=headers,
                )
                redacted[key] = transformed
                log.extend(events)
            return redacted, log
        if isinstance(value, list):
            redacted_list: list[Any] = []
            log = []
            for inner in value:
                transformed, events = self._redact_server_value(
                    inner,
                    session_id=session_id,
                    headers=headers,
                )
                redacted_list.append(transformed)
                log.extend(events)
            return redacted_list, log
        return value, []

    def _restore_server_value(
        self,
        value: Any,
        *,
        session_id: str | None,
        headers: dict[str, str],
    ) -> tuple[Any, list[dict[str, Any]]]:
        if isinstance(value, str):
            return self._restore_server_text(value, session_id=session_id, headers=headers)
        if isinstance(value, dict):
            restored: dict[str, Any] = {}
            log: list[dict[str, Any]] = []
            for key, inner in value.items():
                transformed, events = self._restore_server_value(
                    inner,
                    session_id=session_id,
                    headers=headers,
                )
                restored[key] = transformed
                log.extend(events)
            return restored, log
        if isinstance(value, list):
            restored_list: list[Any] = []
            log = []
            for inner in value:
                transformed, events = self._restore_server_value(
                    inner,
                    session_id=session_id,
                    headers=headers,
                )
                restored_list.append(transformed)
                log.extend(events)
            return restored_list, log
        return value, []

    def _redact_dict(
        self,
        data: dict[str, Any],
        placeholder_mgr: PlaceholderManager,
        session_id: str | None,
    ) -> tuple[dict[str, Any], list[dict]]:
        redacted: dict[str, Any] = {}
        log: list[dict] = []

        for key, value in data.items():
            redacted_value, value_log = self._redact_value(value, placeholder_mgr, session_id)
            redacted[key] = redacted_value
            log.extend(value_log)

        return redacted, log

    def _redact_value(
        self,
        value: Any,
        placeholder_mgr: PlaceholderManager,
        session_id: str | None,
    ) -> tuple[Any, list[dict]]:
        log: list[dict] = []

        if isinstance(value, str):
            entities = self.detector.detect(value)
            if not entities:
                return value, log

            result = placeholder_mgr.redact_text(value, entities)

            for placeholder, original in result.mappings.items():
                entity = next(e for e in entities if e.text == original)
                if self.backend is not None:
                    self.backend.store(
                        placeholder=placeholder,
                        original=original,
                        pii_type=entity.pii_type,
                        session_id=session_id,
                        ttl=self.store_ttl,
                    )
                log.append(
                    {
                        "original": original,
                        "placeholder": placeholder,
                        "type": entity.pii_type,
                        "confidence": entity.confidence,
                    }
                )

            return result.redacted_text, log

        if isinstance(value, dict):
            return self._redact_dict(value, placeholder_mgr, session_id)

        if isinstance(value, list):
            redacted_list: list[Any] = []
            for item in value:
                redacted_item, item_log = self._redact_value(item, placeholder_mgr, session_id)
                redacted_list.append(redacted_item)
                log.extend(item_log)
            return redacted_list, log

        return value, log

    async def _aredact_dict(
        self,
        data: dict[str, Any],
        placeholder_mgr: PlaceholderManager,
        session_id: str | None,
    ) -> tuple[dict[str, Any], list[dict]]:
        redacted: dict[str, Any] = {}
        log: list[dict] = []

        for key, value in data.items():
            redacted_value, value_log = await self._aredact_value(
                value, placeholder_mgr, session_id
            )
            redacted[key] = redacted_value
            log.extend(value_log)

        return redacted, log

    async def _aredact_value(
        self,
        value: Any,
        placeholder_mgr: PlaceholderManager,
        session_id: str | None,
    ) -> tuple[Any, list[dict]]:
        log: list[dict] = []

        if isinstance(value, str):
            entities = await self.detector.adetect(value)
            if not entities:
                return value, log

            result = placeholder_mgr.redact_text(value, entities)

            for placeholder, original in result.mappings.items():
                entity = next(e for e in entities if e.text == original)
                if self.backend is not None:
                    self.backend.store(
                        placeholder=placeholder,
                        original=original,
                        pii_type=entity.pii_type,
                        session_id=session_id,
                        ttl=self.store_ttl,
                    )
                log.append(
                    {
                        "original": original,
                        "placeholder": placeholder,
                        "type": entity.pii_type,
                        "confidence": entity.confidence,
                    }
                )

            return result.redacted_text, log

        if isinstance(value, dict):
            return await self._aredact_dict(value, placeholder_mgr, session_id)

        if isinstance(value, list):
            redacted_list: list[Any] = []
            for item in value:
                redacted_item, item_log = await self._aredact_value(
                    item, placeholder_mgr, session_id
                )
                redacted_list.append(redacted_item)
                log.extend(item_log)
            return redacted_list, log

        return value, log

    def _rehydrate_value(
        self,
        value: Any,
        mappings: dict[str, str],
    ) -> tuple[Any, list[dict]]:
        """Rehydrate PII placeholders in a value, recursively if needed."""
        if isinstance(value, str):
            return self._rehydrate_string(value, mappings)
        if isinstance(value, dict):
            return self._rehydrate_dict(value, mappings)
        if isinstance(value, list):
            return self._rehydrate_list(value, mappings)
        return value, []

    def _rehydrate_string(self, text: str, mappings: dict[str, str]) -> tuple[str, list[dict]]:
        """Rehydrate placeholders in a string."""
        log: list[dict] = []
        rehydrated = text
        for placeholder, original in mappings.items():
            if placeholder in rehydrated:
                rehydrated = rehydrated.replace(placeholder, original)
                log.append({"placeholder": placeholder, "original": original})
        return rehydrated, log

    def _rehydrate_dict(
        self, data: dict[str, Any], mappings: dict[str, str]
    ) -> tuple[dict[str, Any], list[dict]]:
        """Recursively rehydrate a dictionary."""
        log: list[dict] = []
        rehydrated_dict: dict[str, Any] = {}
        for key, value in data.items():
            rehydrated_v, v_log = self._rehydrate_value(value, mappings)
            rehydrated_dict[key] = rehydrated_v
            log.extend(v_log)
        return rehydrated_dict, log

    def _rehydrate_list(
        self, data: list[Any], mappings: dict[str, str]
    ) -> tuple[list[Any], list[dict]]:
        """Recursively rehydrate a list."""
        log: list[dict] = []
        rehydrated_list: list[Any] = []
        for item in data:
            rehydrated_item, item_log = self._rehydrate_value(item, mappings)
            rehydrated_list.append(rehydrated_item)
            log.extend(item_log)
        return rehydrated_list, log


__all__ = [
    "PIIEntity",
    "PIIDetector",
    "PIIPatterns",
    "PIIRestoreAuthorizationError",
    "PIIRestoreIntegrityError",
    "PIIRestoreUnknownTokenError",
    "PIIRuntimeApiError",
    "PIIVaultError",
    "PlaceholderManager",
    "PIIVault",
    "RedactionResult",
    "warmup",
]
