"""Formal verification state and certificate management.

Encapsulates the formal-verification lifecycle: enabling proof-carrying
authorization, injecting ``ProofCarryingMiddleware``, extracting
certificates from middleware context, and verifying certificate
signatures.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import import_module
from typing import Any, Literal
from typing import cast

from .api_client import DashboardClient
from .middleware.base import Middleware, MiddlewareContext


@dataclass
class VerificationInputs:
    """Policy and environment inputs supplied to formal verification."""

    policies: list[dict[str, Any]] | None = None
    grants: list[dict[str, Any]] | None = None
    revocations: list[dict[str, Any]] | None = None
    obligations: list[dict[str, Any]] | None = None
    environment: dict[str, Any] | None = None


@dataclass
class VerificationConfig:
    """Configuration for formal verification lifecycle and transport."""

    enabled: bool = False
    principal: str | None = None
    tenant_id: str | None = None
    mode: str = "enforce"
    provider: Literal["remote", "local"] = "remote"
    api_client: DashboardClient | None = None
    certificate_callback: Callable[..., Any] | None = None
    inputs: VerificationInputs = field(default_factory=VerificationInputs)


class VerificationManager:
    """Manages formal verification state and proof certificates.

    Responsible for creating the ``ProofCarryingMiddleware`` instance,
    extracting ``DecisionCertificate`` dicts from middleware context
    after each tool call, and verifying certificate integrity.
    """

    def __init__(self, config: VerificationConfig) -> None:
        """Initialize from a VerificationConfig.

        Args:
            config: Verification configuration parameters.
        """
        self._enabled = config.enabled
        self._callback = config.certificate_callback
        self._last_certificate: dict[str, Any] | None = None
        self._config = config

    @property
    def enabled(self) -> bool:
        """Whether formal verification is enabled."""
        return self._enabled

    @property
    def last_certificate(self) -> dict[str, Any] | None:
        """Most recent DecisionCertificate from formal verification.

        Returns ``None`` if formal verification is disabled or no tool
        call has been made yet.
        """
        return self._last_certificate

    def build_middleware(self) -> Middleware | None:
        """Build and return ProofCarryingMiddleware if enabled.

        Returns:
            A ``ProofCarryingMiddleware`` instance, or ``None`` when
            formal verification is disabled.

        Raises:
            ValueError: If ``principal`` is not set when enabled.
        """
        if not self._enabled:
            return None
        if not self._config.principal:
            raise ValueError("'principal' is required when formal_verification=True")
        proof_middleware = import_module("ea_agentgate.middleware.proof_middleware")
        proof_carrying_middleware = getattr(proof_middleware, "ProofCarryingMiddleware")
        verification_inputs = self._config.inputs

        return cast(
            Middleware,
            proof_carrying_middleware(
                principal=self._config.principal,
                tenant_id=self._config.tenant_id,
                mode=self._config.mode,
                verification_provider=self._config.provider,
                policies=verification_inputs.policies,
                grants=verification_inputs.grants,
                revocations=verification_inputs.revocations,
                obligations=verification_inputs.obligations,
                environment=verification_inputs.environment,
                api_client=self._config.api_client,
            ),
        )

    def extract_certificate(self, ctx: MiddlewareContext) -> None:
        """Extract proof certificate from middleware context.

        Args:
            ctx: The middleware context after tool execution.
        """
        cert = ctx.metadata.get("proof_certificate")
        if cert is not None:
            self._last_certificate = cert
            if self._callback is not None:
                try:
                    self._callback(cert)
                except (AttributeError, RuntimeError, TypeError, ValueError):
                    pass  # callback errors must not break execution

    def verify_last_certificate(self) -> bool:
        """Verify the most recent certificate's signature.

        Returns:
            ``True`` if the certificate is valid, ``False`` if invalid
            or no certificate exists.
        """
        if self._last_certificate is None:
            return False
        verification_module = import_module("ea_agentgate.verification")
        verify_certificate = getattr(verification_module, "verify_certificate")

        result = verify_certificate(self._last_certificate)
        return cast(bool, result.valid)
