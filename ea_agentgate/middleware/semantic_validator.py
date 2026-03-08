"""Semantic validation middleware using LLM-as-a-judge."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TYPE_CHECKING, cast

from .base import Middleware, MiddlewareContext
from ..exceptions import ValidationError
from ..prompts import get_semantic_prompt

if TYPE_CHECKING:
    from ..backends import CacheBackend, AsyncCacheBackend
    from ..providers.base import LLMProvider


class CheckType(Enum):
    """Types of semantic checks."""

    PROMPT_INJECTION = "prompt_injection"
    PII_DETECTION = "pii_detection"
    TOPIC_RELEVANCE = "topic_relevance"
    TOXICITY = "toxicity"
    CUSTOM = "custom"


@dataclass
class SemanticCheck:
    """Configuration for a semantic check."""

    type: CheckType
    blocking: bool = True
    allowed_topics: list[str] | None = None
    custom_prompt: str | None = None
    custom_system: str | None = None
    threshold: float = 0.8


@dataclass
class CheckResult:
    """Result of a semantic check."""

    check_type: CheckType
    passed: bool
    score: float
    reason: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidatorConfig:
    """Configuration for semantic validator."""

    fail_open: bool = False
    include_inputs: bool = True


@dataclass
class SemanticValidatorConfig:
    """Full configuration for semantic validator."""

    provider: Any = None  # LLMProvider type, forward ref avoids circular import
    checks: list[SemanticCheck] | None = None
    cache: Any = None  # CacheBackend type
    fail_open: bool = False
    include_inputs: bool = True
    async_provider: Any | None = None
    async_cache: Any = None  # AsyncCacheBackend type


class SemanticValidator(Middleware):
    """
    Semantic validation using LLM-as-a-judge.

    Catches encoded/obfuscated attacks that regex-based validation misses.
    Can detect prompt injection, PII, off-topic content, and toxicity.

    Example:
        from ea_agentgate.providers import OpenAIProvider

        validator = SemanticValidator(
            provider=OpenAIProvider(),
            checks=[
                SemanticCheck(type=CheckType.PROMPT_INJECTION),
                SemanticCheck(
                    type=CheckType.TOPIC_RELEVANCE,
                    allowed_topics=["coding", "debugging", "software"],
                ),
                SemanticCheck(
                    type=CheckType.PII_DETECTION,
                    blocking=True,
                ),
            ],
        )

        # Custom check
        validator = SemanticValidator(
            provider=OpenAIProvider(),
            checks=[
                SemanticCheck(
                    type=CheckType.CUSTOM,
                    custom_prompt="Check if this contains financial advice: {input}",
                    custom_system='Respond: {"is_financial_advice": bool, "confidence": 0-1}',
                ),
            ],
        )
    """

    def __init__(
        self,
        *,
        provider: "LLMProvider",
        checks: list[SemanticCheck] | None = None,
        cache: "CacheBackend | None" = None,
        fail_open: bool = False,
        include_inputs: bool = True,
        async_provider: "LLMProvider | None" = None,
        async_cache: "AsyncCacheBackend | None" = None,
    ) -> None:
        """
        Initialize semantic validator.

        Args:
            provider: LLM provider for semantic checks
            checks: List of semantic checks to perform
            cache: Optional cache backend for results
            fail_open: If True, allow requests when checks fail; if False, block them
            include_inputs: Whether to include inputs in checks
            async_provider: Optional async LLM provider
            async_cache: Optional async cache backend
        """
        super().__init__()
        self.provider = provider
        self.checks = checks or [SemanticCheck(type=CheckType.PROMPT_INJECTION)]
        self.cache = cache

        self.config = ValidatorConfig(
            fail_open=fail_open,
            include_inputs=include_inputs,
        )

        self._results: list[CheckResult] = []

        # Async support
        self._async_provider = async_provider
        self._async_cache = async_cache

    @property
    def results(self) -> list[CheckResult]:
        """Get results from last validation."""
        return self._results

    def before(self, ctx: MiddlewareContext) -> None:
        """Run semantic checks before tool execution."""
        self._results = []

        if not self.config.include_inputs:
            return

        input_text = self._serialize_inputs(ctx.inputs)
        if not input_text.strip():
            return

        for check in self.checks:
            result = self._run_check(check, input_text)
            self._results.append(result)

            if not result.passed and check.blocking:
                ctx.trace.block(
                    f"Semantic validation failed: {result.reason}",
                    self.name,
                )
                raise ValidationError(
                    f"Semantic check [{check.type.value}] failed: {result.reason}",
                    middleware=self.name,
                    tool=ctx.tool,
                )

        ctx.metadata["semantic_checks"] = [
            {"type": r.check_type.value, "passed": r.passed, "score": r.score}
            for r in self._results
        ]

    def _serialize_inputs(self, inputs: dict[str, Any]) -> str:
        """Serialize inputs to text for analysis."""
        try:
            return json.dumps(inputs, indent=2, default=str)
        except (TypeError, ValueError):
            return str(inputs)

    def _run_check(
        self,
        check: SemanticCheck,
        input_text: str,
    ) -> CheckResult:
        """Run a single semantic check."""
        cache_key = None
        if self.cache:
            cache_key = self._get_cache_key(check, input_text)
            cached = self.cache.get(cache_key)
            if cached is not None:
                return CheckResult(**cached)

        try:
            result = self._execute_check(check, input_text)
        except (ValueError, json.JSONDecodeError, KeyError, AttributeError) as e:
            # Specific exceptions from LLM response parsing or configuration
            if self.config.fail_open:
                result = CheckResult(
                    check_type=check.type,
                    passed=True,
                    score=0.0,
                    reason=f"Check skipped due to error: {e}",
                    details={"error": str(e), "fail_open": True},
                )
            else:
                result = CheckResult(
                    check_type=check.type,
                    passed=False,
                    score=1.0,
                    reason=f"Check failed due to error: {e}",
                    details={"error": str(e), "fail_open": False},
                )
        except (OSError, RuntimeError, TimeoutError) as e:
            # Catch provider/network errors with fail_open policy
            logging.getLogger(__name__).warning(
                "Error during semantic check: %s", type(e).__name__, exc_info=False
            )
            if self.config.fail_open:
                result = CheckResult(
                    check_type=check.type,
                    passed=True,
                    score=0.0,
                    reason=f"Check skipped due to error: {e}",
                    details={"error": str(e), "fail_open": True},
                )
            else:
                result = CheckResult(
                    check_type=check.type,
                    passed=False,
                    score=1.0,
                    reason=f"Check failed due to error: {e}",
                    details={"error": str(e), "fail_open": False},
                )

        if self.cache and cache_key:
            self.cache.set(
                cache_key,
                {
                    "check_type": result.check_type,
                    "passed": result.passed,
                    "score": result.score,
                    "reason": result.reason,
                    "details": result.details,
                },
                ttl=3600,
            )

        return result

    def _execute_check(self, check: SemanticCheck, input_text: str) -> CheckResult:
        """Execute the actual LLM check."""
        if check.type == CheckType.CUSTOM:
            if not check.custom_prompt:
                raise ValueError("Custom check requires custom_prompt")
            system = check.custom_system or "Respond with valid JSON."
            prompt = check.custom_prompt.format(input=input_text)
        else:
            prompts = get_semantic_prompt(check.type.value)
            system = prompts["system"]
            prompt = prompts["prompt"]

            if check.type == CheckType.TOPIC_RELEVANCE:
                topics = ", ".join(check.allowed_topics or ["general"])
                prompt = prompt.format(input=input_text, topics=topics)
            else:
                prompt = prompt.format(input=input_text)

        response = self.provider.complete(prompt, system=system, temperature=0.0)
        return self._parse_response(check, response.content)

    def _parse_response(self, check: SemanticCheck, content: str) -> CheckResult:
        """Parse LLM response into CheckResult."""
        try:
            start = content.find("{")
            end = content.rfind("}") + 1
            if 0 <= start < end:
                content = content[start:end]
            data = json.loads(content)
        except json.JSONDecodeError:
            return CheckResult(
                check_type=check.type,
                passed=False,
                score=0.0,
                reason="Failed to parse LLM response",
                details={"raw_response": content},
            )

        confidence = data.get("confidence", 0.5)

        if check.type == CheckType.PROMPT_INJECTION:
            is_injection = data.get("is_injection", False)
            return CheckResult(
                check_type=check.type,
                passed=not is_injection or confidence < check.threshold,
                score=confidence if is_injection else 1 - confidence,
                reason=data.get("reason", "No reason provided"),
                details=data,
            )

        if check.type == CheckType.PII_DETECTION:
            contains_pii = data.get("contains_pii", False)
            return CheckResult(
                check_type=check.type,
                passed=not contains_pii or confidence < check.threshold,
                score=confidence if contains_pii else 1 - confidence,
                reason=data.get("reason", "No reason provided"),
                details={"pii_types": data.get("pii_types", []), **data},
            )

        if check.type == CheckType.TOPIC_RELEVANCE:
            is_relevant = data.get("is_relevant", True)
            return CheckResult(
                check_type=check.type,
                passed=is_relevant or confidence < check.threshold,
                score=confidence if is_relevant else 1 - confidence,
                reason=data.get("reason", "No reason provided"),
                details={"matched_topic": data.get("matched_topic"), **data},
            )

        if check.type == CheckType.TOXICITY:
            is_toxic = data.get("is_toxic", False)
            return CheckResult(
                check_type=check.type,
                passed=not is_toxic or confidence < check.threshold,
                score=confidence if is_toxic else 1 - confidence,
                reason=data.get("reason", "No reason provided"),
                details={"toxicity_types": data.get("toxicity_types", []), **data},
            )

        # Custom check type (CheckType.CUSTOM)
        passed = not data.get("flagged", False)
        return CheckResult(
            check_type=check.type,
            passed=passed or confidence < check.threshold,
            score=confidence,
            reason=data.get("reason", "Custom check completed"),
            details=data,
        )

    def _get_cache_key(self, check: SemanticCheck, input_text: str) -> str:
        """Generate cache key for check result."""
        key_data = f"{check.type.value}:{check.threshold}:{input_text}"
        if check.allowed_topics:
            key_data += f":{','.join(sorted(check.allowed_topics))}"
        if check.custom_prompt:
            key_data += f":{check.custom_prompt}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:32]

    # -------------------------------------------------------------------------
    # Async Methods
    # -------------------------------------------------------------------------

    def is_async_native(self) -> bool:
        """Return True if async provider is configured."""
        return self._async_provider is not None

    async def abefore(self, ctx: MiddlewareContext) -> None:
        """Async run semantic checks before tool execution."""
        if self._async_provider is None:
            # Fall back to sync via thread pool
            await asyncio.to_thread(self.before, ctx)
            return

        self._results = []

        if not self.config.include_inputs:
            return

        input_text = self._serialize_inputs(ctx.inputs)
        if not input_text.strip():
            return

        for check in self.checks:
            result = await self._arun_check(check, input_text)
            self._results.append(result)

            if not result.passed and check.blocking:
                ctx.trace.block(
                    f"Semantic validation failed: {result.reason}",
                    self.name,
                )
                raise ValidationError(
                    f"Semantic check [{check.type.value}] failed: {result.reason}",
                    middleware=self.name,
                    tool=ctx.tool,
                )

        ctx.metadata["semantic_checks"] = [
            {"type": r.check_type.value, "passed": r.passed, "score": r.score}
            for r in self._results
        ]

    async def _aget_cached_result(
        self, check: SemanticCheck, input_text: str
    ) -> tuple[str | None, CheckResult | None]:
        """Retrieve cached result if available. Returns (cache_key, result)."""
        cache_key = self._get_cache_key(check, input_text)

        if self._async_cache:
            cached = await self._async_cache.aget(cache_key)
            if cached is not None:
                return cache_key, CheckResult(**cached)
        elif self.cache:
            cached = await asyncio.to_thread(self.cache.get, cache_key)
            if cached is not None:
                return cache_key, CheckResult(**cached)

        return cache_key, None

    def _create_error_result(
        self, check: SemanticCheck, error: Exception, is_parsing_error: bool = False
    ) -> CheckResult:
        """Create a CheckResult for an error condition."""
        error_types = (ValueError, json.JSONDecodeError, KeyError, AttributeError)
        if not (is_parsing_error or isinstance(error, error_types)):
            logging.getLogger(__name__).warning(
                "Unexpected error during semantic check: %s", type(error).__name__, exc_info=False
            )

        if self.config.fail_open:
            reason = f"Check skipped due to error: {error}"
        else:
            reason = f"Check failed due to error: {error}"
        return CheckResult(
            check_type=check.type,
            passed=self.config.fail_open,
            score=0.0 if self.config.fail_open else 1.0,
            reason=reason,
            details={"error": str(error), "fail_open": self.config.fail_open},
        )

    async def _aset_cached_result(self, cache_key: str, result: CheckResult) -> None:
        """Cache a check result."""
        cache_data = {
            "check_type": result.check_type,
            "passed": result.passed,
            "score": result.score,
            "reason": result.reason,
            "details": result.details,
        }
        if self._async_cache:
            await self._async_cache.aset(cache_key, cache_data, ttl=3600)
        elif self.cache:
            await asyncio.to_thread(self.cache.set, cache_key, cache_data, None, 3600)

    async def _arun_check(
        self,
        check: SemanticCheck,
        input_text: str,
    ) -> CheckResult:
        """Async run a single semantic check."""
        # Try to get from cache
        cache_key, cached_result = await self._aget_cached_result(check, input_text)
        if cached_result is not None:
            return cached_result

        # Execute check and handle errors
        try:
            result = await self._aexecute_check(check, input_text)
        except (ValueError, json.JSONDecodeError, KeyError, AttributeError) as e:
            result = self._create_error_result(check, e, is_parsing_error=True)
        except (OSError, RuntimeError, TimeoutError) as e:
            result = self._create_error_result(check, e, is_parsing_error=False)

        # Cache result if we have a cache key
        if cache_key:
            await self._aset_cached_result(cache_key, result)

        return result

    async def _aexecute_check(self, check: SemanticCheck, input_text: str) -> CheckResult:
        """Async execute the actual LLM check."""
        if check.type == CheckType.CUSTOM:
            if not check.custom_prompt:
                raise ValueError("Custom check requires custom_prompt")
            system = check.custom_system or "Respond with valid JSON."
            prompt = check.custom_prompt.format(input=input_text)
        else:
            prompts = get_semantic_prompt(check.type.value)
            system = prompts["system"]
            prompt = prompts["prompt"]

            if check.type == CheckType.TOPIC_RELEVANCE:
                topics = ", ".join(check.allowed_topics or ["general"])
                prompt = prompt.format(input=input_text, topics=topics)
            else:
                prompt = prompt.format(input=input_text)

        # _async_provider is expected to be initialized in abefore().
        provider = self._async_provider
        if provider is None:
            raise RuntimeError("Async provider is not initialized")
        response = await cast(Any, provider).acomplete(prompt, system=system, temperature=0.0)
        return self._parse_response(check, response.content)


__all__ = [
    "SemanticValidator",
    "SemanticCheck",
    "CheckType",
    "CheckResult",
]
