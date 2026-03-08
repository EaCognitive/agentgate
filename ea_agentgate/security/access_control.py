"""
Access control for PII operations - SOC 2 CC6.1 and HIPAA §164.312(a)(1) compliant.

Provides:
- Role-based access control (RBAC)
- Minimum necessary access enforcement
- Access attempt logging
- Permission checking hooks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, TYPE_CHECKING
from collections.abc import Callable

from .audit import AuditEventType

if TYPE_CHECKING:
    from .audit import ComplianceAuditLog


# =============================================================================
# Permissions
# =============================================================================


class Permission(str, Enum):
    """Permissions for PII vault operations."""

    # PII Operations
    PII_STORE = "pii:store"
    PII_RETRIEVE = "pii:retrieve"
    PII_DELETE = "pii:delete"
    PII_BULK_RETRIEVE = "pii:bulk_retrieve"
    PII_CLEAR_SESSION = "pii:clear_session"

    # Admin Operations
    PII_CLEAR_ALL = "pii:clear_all"
    PII_EXPORT = "pii:export"
    PII_AUDIT_READ = "pii:audit_read"

    # Key Management
    KEY_ROTATE = "key:rotate"
    KEY_VIEW = "key:view"

    # Configuration
    CONFIG_VIEW = "config:view"
    CONFIG_MODIFY = "config:modify"


# =============================================================================
# Roles
# =============================================================================


@dataclass
class Role:
    """
    Role definition with associated permissions.

    Predefined roles follow principle of least privilege.
    """

    name: str
    permissions: set[Permission]
    description: str = ""

    def has_permission(self, permission: Permission) -> bool:
        """Check if role has a specific permission."""
        return permission in self.permissions


# Predefined roles for HIPAA compliance
class Roles:
    """Predefined roles for PII vault access."""

    # Can only retrieve PII for rehydration (minimal access)
    PII_VIEWER = Role(
        name="pii_viewer",
        permissions={
            Permission.PII_RETRIEVE,
        },
        description="Read-only access for PII rehydration",
    )

    # Can store and retrieve PII (standard middleware operation)
    PII_PROCESSOR = Role(
        name="pii_processor",
        permissions={
            Permission.PII_STORE,
            Permission.PII_RETRIEVE,
            Permission.PII_BULK_RETRIEVE,
        },
        description="Process PII through the vault (middleware)",
    )

    # Can manage sessions (application user)
    PII_USER = Role(
        name="pii_user",
        permissions={
            Permission.PII_STORE,
            Permission.PII_RETRIEVE,
            Permission.PII_BULK_RETRIEVE,
            Permission.PII_CLEAR_SESSION,
        },
        description="User-level PII operations within own session",
    )

    # Can perform all PII operations
    PII_ADMIN = Role(
        name="pii_admin",
        permissions={
            Permission.PII_STORE,
            Permission.PII_RETRIEVE,
            Permission.PII_DELETE,
            Permission.PII_BULK_RETRIEVE,
            Permission.PII_CLEAR_SESSION,
            Permission.PII_CLEAR_ALL,
            Permission.PII_EXPORT,
            Permission.CONFIG_VIEW,
            Permission.CONFIG_MODIFY,
        },
        description="Full PII vault administration",
    )

    # Read-only access to audit logs (compliance auditors)
    AUDITOR = Role(
        name="auditor",
        permissions={
            Permission.PII_AUDIT_READ,
            Permission.CONFIG_VIEW,
        },
        description="Compliance auditor - audit log access only",
    )

    # System administrator with key management
    SYSTEM_ADMIN = Role(
        name="system_admin",
        permissions=set(Permission),  # All permissions
        description="Full system access including key management",
    )

    @staticmethod
    def get_all_roles() -> list[Role]:
        """Return all predefined roles."""
        return [
            Roles.PII_VIEWER,
            Roles.PII_PROCESSOR,
            Roles.PII_USER,
            Roles.PII_ADMIN,
            Roles.AUDITOR,
            Roles.SYSTEM_ADMIN,
        ]

    @staticmethod
    def get_role_by_name(name: str) -> Role | None:
        """Get a role by name."""
        for role in Roles.get_all_roles():
            if role.name == name:
                return role
        return None


# =============================================================================
# Exceptions
# =============================================================================


class AccessDeniedError(Exception):
    """Access to resource was denied."""

    def __init__(
        self,
        message: str,
        user_id: str | None = None,
        permission: Permission | None = None,
        resource: str | None = None,
    ):
        super().__init__(message)
        self.user_id = user_id
        self.permission = permission
        self.resource = resource


class AuthenticationRequiredError(Exception):
    """Operation requires authentication."""


# =============================================================================
# Access Control Provider Protocol
# =============================================================================


class AccessControlProvider(Protocol):
    """Protocol for access control implementations."""

    def check_permission(
        self,
        user_id: str,
        permission: Permission,
        resource: str | None = None,
    ) -> bool:
        """
        Check if user has permission.

        Args:
            user_id: User identifier
            permission: Required permission
            resource: Optional resource being accessed

        Returns:
            True if access is allowed
        """
        raise NotImplementedError

    def require_permission(
        self,
        user_id: str,
        permission: Permission,
        resource: str | None = None,
    ) -> None:
        """
        Require permission or raise AccessDeniedError.

        Args:
            user_id: User identifier
            permission: Required permission
            resource: Optional resource being accessed

        Raises:
            AccessDeniedError: If permission is denied
        """
        raise NotImplementedError


# =============================================================================
# Access Control Context
# =============================================================================


@dataclass
class AccessContext:
    """
    Context for access control decisions.

    Contains all information needed to make access control decisions.
    """

    user_id: str
    roles: list[Role]
    session_id: str | None = None
    agent_id: str | None = None
    source_ip: str | None = None
    authenticated: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def has_permission(self, permission: Permission) -> bool:
        """Check if any role grants the permission."""
        return any(role.has_permission(permission) for role in self.roles)

    def has_role(self, role_name: str) -> bool:
        """Check if user has a specific role."""
        return any(role.name == role_name for role in self.roles)


# =============================================================================
# Simple RBAC Implementation
# =============================================================================


class SimpleRBAC:
    """
    Simple role-based access control implementation.

    For production use, integrate with your identity provider
    (Auth0, Okta, AWS IAM, etc.)

    Example:
        rbac = SimpleRBAC()
        rbac.assign_role("user123", Roles.PII_USER)

        # Check permission
        if rbac.check_permission("user123", Permission.PII_STORE):
            vault.store(...)

        # Or require it (raises AccessDeniedError if denied)
        rbac.require_permission("user123", Permission.PII_STORE)
        vault.store(...)
    """

    def __init__(
        self,
        audit_log: "ComplianceAuditLog | None" = None,
        default_role: Role | None = None,
    ):
        """
        Initialize RBAC.

        Args:
            audit_log: Optional audit log for access attempts
            default_role: Default role for unknown users (None = deny all)
        """
        self._user_roles: dict[str, list[Role]] = {}
        self._audit_log = audit_log
        self._default_role = default_role

        # Session ownership mapping (user_id -> session_ids)
        self._session_ownership: dict[str, set[str]] = {}

    def assign_role(self, user_id: str, role: Role) -> None:
        """Assign a role to a user."""
        if user_id not in self._user_roles:
            self._user_roles[user_id] = []

        if role not in self._user_roles[user_id]:
            self._user_roles[user_id].append(role)

    def revoke_role(self, user_id: str, role: Role) -> None:
        """Revoke a role from a user."""
        if user_id in self._user_roles:
            self._user_roles[user_id] = [
                r for r in self._user_roles[user_id] if r.name != role.name
            ]

    def get_roles(self, user_id: str) -> list[Role]:
        """Get all roles for a user."""
        roles = self._user_roles.get(user_id, [])
        if not roles and self._default_role:
            return [self._default_role]
        return roles

    def register_session(self, user_id: str, session_id: str) -> None:
        """Register session ownership for a user."""
        if user_id not in self._session_ownership:
            self._session_ownership[user_id] = set()
        self._session_ownership[user_id].add(session_id)

    def owns_session(self, user_id: str, session_id: str) -> bool:
        """Check if user owns a session."""
        return session_id in self._session_ownership.get(user_id, set())

    def check_permission(
        self,
        user_id: str,
        permission: Permission,
        resource: str | None = None,
        session_id: str | None = None,
    ) -> bool:
        """
        Check if user has permission.

        Implements minimum necessary access:
        - Session-scoped permissions only apply to owned sessions
        """
        roles = self.get_roles(user_id)

        # Check basic permission
        has_perm = any(role.has_permission(permission) for role in roles)

        if not has_perm:
            self._log_access_denied(user_id, permission, resource, "permission_denied")
            return False

        # For session operations, check ownership (minimum necessary)
        if session_id and permission in {
            Permission.PII_CLEAR_SESSION,
            Permission.PII_RETRIEVE,
            Permission.PII_BULK_RETRIEVE,
        }:
            # Admins can access any session
            if any(role.has_permission(Permission.PII_CLEAR_ALL) for role in roles):
                return True

            # Others can only access own sessions
            if not self.owns_session(user_id, session_id):
                self._log_access_denied(
                    user_id, permission, resource, f"session_not_owned:{session_id}"
                )
                return False

        return True

    def require_permission(
        self,
        user_id: str,
        permission: Permission,
        resource: str | None = None,
        session_id: str | None = None,
    ) -> None:
        """
        Require permission or raise AccessDeniedError.
        """
        if not self.check_permission(user_id, permission, resource, session_id):
            raise AccessDeniedError(
                f"User {user_id} does not have permission {permission.value}",
                user_id=user_id,
                permission=permission,
                resource=resource,
            )

    def get_context(
        self,
        user_id: str,
        session_id: str | None = None,
        agent_id: str | None = None,
        source_ip: str | None = None,
    ) -> AccessContext:
        """Create access context for a user."""
        return AccessContext(
            user_id=user_id,
            roles=self.get_roles(user_id),
            session_id=session_id,
            agent_id=agent_id,
            source_ip=source_ip,
            authenticated=user_id in self._user_roles,
        )

    def _log_access_denied(
        self,
        user_id: str,
        permission: Permission,
        resource: str | None,
        reason: str,
    ) -> None:
        """Log access denied event."""
        if self._audit_log:
            self._audit_log.log(
                event_type=AuditEventType.ACCESS_DENIED,
                user_id=user_id,
                resource=resource,
                action=permission.value,
                success=False,
                error_message=reason,
            )


# =============================================================================
# Decorators for Access Control
# =============================================================================


def require_permission(permission: Permission):
    """
    Decorator to require permission for a function.

    The decorated function must have 'user_id' as first argument
    or in kwargs, and 'rbac' in kwargs.

    Example:
        @require_permission(Permission.PII_STORE)
        def store_pii(user_id: str, placeholder: str, original: str, rbac: SimpleRBAC):
            ...
    """

    def decorator(func: Callable) -> Callable:
        """Wrap the function with a permission check."""

        def wrapper(*args, **kwargs):
            """Enforce the required permission before calling the function."""
            # Get user_id from args or kwargs
            user_id = kwargs.get("user_id") or (args[0] if args else None)
            rbac = kwargs.get("rbac")

            if not user_id:
                raise AuthenticationRequiredError("user_id required")

            if not rbac:
                raise ValueError("rbac required in kwargs")

            # Check permission
            session_id = kwargs.get("session_id")
            resource = kwargs.get("resource")
            rbac.require_permission(user_id, permission, resource, session_id)

            return func(*args, **kwargs)

        return wrapper

    return decorator


__all__ = [
    "Permission",
    "Role",
    "Roles",
    "AccessDeniedError",
    "AuthenticationRequiredError",
    "AccessControlProvider",
    "AccessContext",
    "SimpleRBAC",
    "require_permission",
]
