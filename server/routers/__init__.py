"""API router exports for policy-governance focused runtime."""

import os

from .auth import router as auth_router, get_current_user, require_admin
from .auth_mfa import router as auth_mfa_router
from .passkey import router as passkey_router
from .pii import router as pii_router
from .pii_compliance import router as pii_compliance_router
from .policy_governance import router as policy_governance_router
from .policies import router as policies_router
from .audit import router as audit_router
from .approvals import router as approvals_router
from .datasets import router as datasets_router
from .users import router as users_router
from .settings import router as settings_router
from .device_auth import router as device_auth_router
from .api_keys import router as api_keys_router
from .setup import router as setup_router
from .mcp_mfa_callback import router as mcp_mfa_callback_router
from .verification import router as verification_router
from .traces import router as traces_router
from .health import router as health_router
from ..policy_governance.kernel.master_key_router import router as master_key_router

_environment = os.getenv("AGENTGATE_ENV", "development")
TEST_ROUTER = None
if _environment != "production":
    from .test import router as TEST_ROUTER  # type: ignore[assignment]

__all__ = [
    "auth_router",
    "auth_mfa_router",
    "passkey_router",
    "pii_router",
    "pii_compliance_router",
    "policy_governance_router",
    "policies_router",
    "audit_router",
    "approvals_router",
    "datasets_router",
    "users_router",
    "settings_router",
    "device_auth_router",
    "api_keys_router",
    "setup_router",
    "mcp_mfa_callback_router",
    "verification_router",
    "traces_router",
    "health_router",
    "master_key_router",
    "TEST_ROUTER",
    "get_current_user",
    "require_admin",
]
