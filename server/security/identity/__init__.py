"""Identity provider, role, and risk policy services."""

from .adapter import IdentityProviderAdapter, ProviderClaims
from .service import (
    SUPPORTED_PROVIDER_MODES,
    get_identity_provider_mode,
    local_password_auth_allowed,
    provider_capabilities,
    validate_provider_token,
)
from .roles import (
    CANONICAL_ROLES,
    LEGACY_ROLE_ALIASES,
    default_risk_for_role,
    is_legacy_alias_enabled,
    normalize_role,
    validate_role,
)
from .store import (
    ensure_user_identity_records,
    get_principal_risk,
    get_roles_for_principal,
)
from .policy import (
    evaluate_policy_decision,
    normalize_assurance_level,
    normalize_risk_level,
    required_assurance_for_risk,
)
from .mcp_access import (
    evaluate_mcp_privilege,
    extract_scopes_from_claims,
    mcp_privileged_roles,
    mcp_required_scopes,
    mcp_scope_enforced,
)

__all__ = [
    "IdentityProviderAdapter",
    "ProviderClaims",
    "SUPPORTED_PROVIDER_MODES",
    "get_identity_provider_mode",
    "local_password_auth_allowed",
    "provider_capabilities",
    "validate_provider_token",
    "CANONICAL_ROLES",
    "LEGACY_ROLE_ALIASES",
    "default_risk_for_role",
    "is_legacy_alias_enabled",
    "normalize_role",
    "validate_role",
    "ensure_user_identity_records",
    "get_principal_risk",
    "get_roles_for_principal",
    "evaluate_policy_decision",
    "normalize_assurance_level",
    "normalize_risk_level",
    "required_assurance_for_risk",
    "evaluate_mcp_privilege",
    "extract_scopes_from_claims",
    "mcp_privileged_roles",
    "mcp_required_scopes",
    "mcp_scope_enforced",
]
