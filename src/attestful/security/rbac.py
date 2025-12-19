"""
Role-Based Access Control (RBAC) for Attestful.

Provides:
- Role definitions (admin, analyst, operator, viewer)
- Permission enforcement
- User management
- Audit logging of access

Step 8.1.8 and 11.4.3 of instructions.txt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from functools import wraps
from typing import TYPE_CHECKING, Any, Callable
from uuid import uuid4

from attestful.core.logging import get_logger

if TYPE_CHECKING:
    from attestful.security.audit import AuditLog

logger = get_logger(__name__)


# =============================================================================
# Enums
# =============================================================================


class Role(str, Enum):
    """User roles with increasing privilege levels."""

    VIEWER = "viewer"  # Read-only access to reports and dashboards
    ANALYST = "analyst"  # Can view and analyze, limited run capability
    OPERATOR = "operator"  # Can run scans and collections
    ADMIN = "admin"  # Full access including user management


class Permission(str, Enum):
    """Available permissions in the system."""

    # Scan permissions
    SCAN_VIEW = "scan:view"
    SCAN_RUN = "scan:run"
    SCAN_DELETE = "scan:delete"

    # Collection permissions
    COLLECT_VIEW = "collect:view"
    COLLECT_RUN = "collect:run"
    COLLECT_DELETE = "collect:delete"

    # Report permissions
    REPORT_VIEW = "report:view"
    REPORT_GENERATE = "report:generate"
    REPORT_DELETE = "report:delete"

    # Credential permissions
    CREDENTIAL_VIEW = "credential:view"
    CREDENTIAL_MANAGE = "credential:manage"

    # User management permissions
    USER_VIEW = "user:view"
    USER_MANAGE = "user:manage"

    # Configuration permissions
    CONFIG_VIEW = "config:view"
    CONFIG_MANAGE = "config:manage"

    # OSCAL permissions
    OSCAL_VIEW = "oscal:view"
    OSCAL_MANAGE = "oscal:manage"

    # Remediation permissions
    REMEDIATE_VIEW = "remediate:view"
    REMEDIATE_EXECUTE = "remediate:execute"


# =============================================================================
# Role-Permission Mappings
# =============================================================================


# Define which permissions each role has
ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.VIEWER: {
        Permission.SCAN_VIEW,
        Permission.COLLECT_VIEW,
        Permission.REPORT_VIEW,
        Permission.OSCAL_VIEW,
        Permission.REMEDIATE_VIEW,
    },
    Role.ANALYST: {
        # Include viewer permissions
        Permission.SCAN_VIEW,
        Permission.COLLECT_VIEW,
        Permission.REPORT_VIEW,
        Permission.OSCAL_VIEW,
        Permission.REMEDIATE_VIEW,
        # Additional analyst permissions
        Permission.REPORT_GENERATE,
        Permission.CREDENTIAL_VIEW,
        Permission.USER_VIEW,
        Permission.CONFIG_VIEW,
    },
    Role.OPERATOR: {
        # Include analyst permissions
        Permission.SCAN_VIEW,
        Permission.COLLECT_VIEW,
        Permission.REPORT_VIEW,
        Permission.OSCAL_VIEW,
        Permission.REMEDIATE_VIEW,
        Permission.REPORT_GENERATE,
        Permission.CREDENTIAL_VIEW,
        Permission.USER_VIEW,
        Permission.CONFIG_VIEW,
        # Additional operator permissions
        Permission.SCAN_RUN,
        Permission.COLLECT_RUN,
        Permission.REMEDIATE_EXECUTE,
        Permission.OSCAL_MANAGE,
    },
    Role.ADMIN: {
        # All permissions
        Permission.SCAN_VIEW,
        Permission.SCAN_RUN,
        Permission.SCAN_DELETE,
        Permission.COLLECT_VIEW,
        Permission.COLLECT_RUN,
        Permission.COLLECT_DELETE,
        Permission.REPORT_VIEW,
        Permission.REPORT_GENERATE,
        Permission.REPORT_DELETE,
        Permission.CREDENTIAL_VIEW,
        Permission.CREDENTIAL_MANAGE,
        Permission.USER_VIEW,
        Permission.USER_MANAGE,
        Permission.CONFIG_VIEW,
        Permission.CONFIG_MANAGE,
        Permission.OSCAL_VIEW,
        Permission.OSCAL_MANAGE,
        Permission.REMEDIATE_VIEW,
        Permission.REMEDIATE_EXECUTE,
    },
}


# =============================================================================
# User Model
# =============================================================================


@dataclass
class RBACUser:
    """User representation for RBAC."""

    id: str
    email: str
    role: Role
    name: str = ""
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    custom_permissions: set[Permission] = field(default_factory=set)
    denied_permissions: set[Permission] = field(default_factory=set)

    def get_effective_permissions(self) -> set[Permission]:
        """Get all effective permissions for this user."""
        if not self.is_active:
            return set()

        # Start with role permissions
        permissions = ROLE_PERMISSIONS.get(self.role, set()).copy()

        # Add custom permissions
        permissions.update(self.custom_permissions)

        # Remove denied permissions
        permissions -= self.denied_permissions

        return permissions

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "role": self.role.value,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
        }


# =============================================================================
# RBAC Manager
# =============================================================================


# Email validation pattern
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


class RBACManager:
    """
    Manages role-based access control.

    Provides user management and permission checking with
    optional audit logging integration.
    """

    def __init__(self) -> None:
        """Initialize RBAC manager."""
        self._users: dict[str, RBACUser] = {}
        self._users_by_email: dict[str, str] = {}
        self._audit_log: AuditLog | None = None

    def set_audit_log(self, audit_log: AuditLog) -> None:
        """Set the audit log for permission tracking."""
        self._audit_log = audit_log

    def _validate_email(self, email: str) -> None:
        """Validate email format and check for injection attempts."""
        if not email:
            raise ValueError("Email cannot be empty")

        # Check for SQL injection patterns
        dangerous_patterns = ["'", '"', ";", "--", "/*", "*/", "DROP", "DELETE", "INSERT", "UPDATE"]
        upper_email = email.upper()
        for pattern in dangerous_patterns:
            if pattern.upper() in upper_email:
                raise ValueError(f"Invalid characters in email: {pattern}")

        # Check format
        if not EMAIL_PATTERN.match(email):
            raise ValueError(f"Invalid email format: {email}")

    def create_user(
        self,
        email: str,
        role: Role,
        name: str = "",
    ) -> RBACUser:
        """
        Create a new user.

        Args:
            email: User email address.
            role: User role.
            name: User display name.

        Returns:
            The created user.

        Raises:
            ValueError: If email is invalid or already exists.
        """
        self._validate_email(email)

        if email.lower() in self._users_by_email:
            raise ValueError(f"User with email {email} already exists")

        user_id = str(uuid4())
        user = RBACUser(
            id=user_id,
            email=email.lower(),
            role=role,
            name=name or email.split("@")[0],
        )

        self._users[user_id] = user
        self._users_by_email[email.lower()] = user_id

        logger.info(f"Created user {email} with role {role.value}")
        return user

    def get_user(self, user_id: str) -> RBACUser | None:
        """Get a user by ID."""
        return self._users.get(user_id)

    def get_user_by_email(self, email: str) -> RBACUser | None:
        """Get a user by email."""
        user_id = self._users_by_email.get(email.lower())
        if user_id:
            return self._users.get(user_id)
        return None

    def has_permission(self, user: RBACUser, permission: Permission) -> bool:
        """
        Check if a user has a specific permission.

        Args:
            user: The user to check.
            permission: The permission to verify.

        Returns:
            True if user has the permission.
        """
        result = permission in user.get_effective_permissions()

        # Log permission check if audit log is set
        if self._audit_log:
            from attestful.security.audit import AuditAction

            self._audit_log.log(
                action=AuditAction.PERMISSION_CHECK,
                user=user.email,
                details={
                    "permission": permission.value,
                    "granted": result,
                    "role": user.role.value,
                },
            )

        return result

    def grant_permission(
        self,
        user: RBACUser,
        permission: Permission,
        granted_by: RBACUser,
    ) -> None:
        """
        Grant a custom permission to a user.

        Args:
            user: User to grant permission to.
            permission: Permission to grant.
            granted_by: User granting the permission.

        Raises:
            PermissionError: If granting user lacks permission.
        """
        # Only admins can grant permissions
        if granted_by.role != Role.ADMIN:
            raise PermissionError(
                f"User {granted_by.email} does not have permission to grant permissions"
            )

        user.custom_permissions.add(permission)
        logger.info(f"Granted {permission.value} to {user.email} by {granted_by.email}")

    def revoke_permission(
        self,
        user: RBACUser,
        permission: Permission,
        revoked_by: RBACUser,
    ) -> None:
        """
        Revoke a permission from a user.

        Args:
            user: User to revoke permission from.
            permission: Permission to revoke.
            revoked_by: User revoking the permission.

        Raises:
            PermissionError: If revoking user lacks permission.
        """
        if revoked_by.role != Role.ADMIN:
            raise PermissionError(
                f"User {revoked_by.email} does not have permission to revoke permissions"
            )

        user.custom_permissions.discard(permission)
        user.denied_permissions.add(permission)
        logger.info(f"Revoked {permission.value} from {user.email} by {revoked_by.email}")

    def change_role(
        self,
        user: RBACUser,
        new_role: Role,
        changed_by: RBACUser,
    ) -> None:
        """
        Change a user's role.

        Args:
            user: User to change role for.
            new_role: New role to assign.
            changed_by: User making the change.

        Raises:
            PermissionError: If changing user lacks permission.
        """
        # Only admins can change roles
        if changed_by.role != Role.ADMIN:
            raise PermissionError(
                f"User {changed_by.email} does not have permission to change roles"
            )

        # Prevent self-demotion from admin (must have another admin do it)
        if user.id == changed_by.id and user.role == Role.ADMIN and new_role != Role.ADMIN:
            raise PermissionError("Admins cannot demote themselves")

        old_role = user.role
        user.role = new_role
        logger.info(
            f"Changed role for {user.email} from {old_role.value} to {new_role.value} "
            f"by {changed_by.email}"
        )

    def deactivate_user(self, user: RBACUser, deactivated_by: RBACUser) -> None:
        """
        Deactivate a user.

        Args:
            user: User to deactivate.
            deactivated_by: User performing the deactivation.

        Raises:
            PermissionError: If deactivating user lacks permission.
        """
        if deactivated_by.role != Role.ADMIN:
            raise PermissionError(
                f"User {deactivated_by.email} does not have permission to deactivate users"
            )

        user.is_active = False
        logger.info(f"Deactivated user {user.email} by {deactivated_by.email}")

    def list_users(self) -> list[RBACUser]:
        """List all users."""
        return list(self._users.values())


# =============================================================================
# Permission Decorator
# =============================================================================


def check_permission(
    permission: Permission,
    rbac_manager: RBACManager,
) -> Callable:
    """
    Decorator to check permission before executing a function.

    The decorated function must have 'user' as its first argument.

    Args:
        permission: Required permission.
        rbac_manager: RBAC manager instance.

    Returns:
        Decorated function.
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(user: RBACUser, *args: Any, **kwargs: Any) -> Any:
            if not rbac_manager.has_permission(user, permission):
                raise PermissionError(
                    f"User {user.email} does not have permission {permission.value}"
                )
            return func(user, *args, **kwargs)

        return wrapper

    return decorator


# =============================================================================
# Module Exports
# =============================================================================


__all__ = [
    "Role",
    "Permission",
    "RBACUser",
    "RBACManager",
    "ROLE_PERMISSIONS",
    "check_permission",
]
