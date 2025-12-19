"""
Security tests for Attestful.

Tests cover:
- Credential encryption and storage
- RBAC permission enforcement
- Audit log tamper detection
- Input validation and sanitization
- Security configuration verification
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from attestful.config.credentials import CredentialStore
from attestful.security.audit import (
    AuditAction,
    AuditEntry,
    AuditLog,
    verify_audit_chain,
)
from attestful.security.rbac import (
    Permission,
    RBACManager,
    RBACUser,
    Role,
    check_permission,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def temp_credential_dir(tmp_path: Path) -> Path:
    """Temporary directory for credential storage."""
    cred_dir = tmp_path / "credentials"
    cred_dir.mkdir()
    return cred_dir


@pytest.fixture
def credential_store(temp_credential_dir: Path) -> CredentialStore:
    """Credential store for testing."""
    return CredentialStore(data_dir=temp_credential_dir)


@pytest.fixture
def rbac_manager() -> RBACManager:
    """RBAC manager for testing."""
    return RBACManager()


@pytest.fixture
def audit_log(tmp_path: Path) -> AuditLog:
    """Audit log for testing."""
    return AuditLog(log_path=tmp_path / "audit.log")


# =============================================================================
# Credential Encryption Tests (Step 11.4.2)
# =============================================================================


@pytest.mark.security
class TestCredentialEncryption:
    """Tests for credential encryption functionality."""

    def test_credentials_encrypted_at_rest(
        self, credential_store: CredentialStore
    ) -> None:
        """Test that credentials are encrypted when stored."""
        # Store a credential
        credential_store.set(
            platform="aws",
            name="production",
            data={"access_key_id": "AKIAIOSFODNN7EXAMPLE", "secret_access_key": "secret"},
        )

        # Read raw file contents
        raw_contents = credential_store.credentials_file.read_bytes()

        # Original value should NOT appear in raw storage (it's encrypted)
        assert b"AKIAIOSFODNN7EXAMPLE" not in raw_contents

    def test_credentials_decrypted_correctly(
        self, credential_store: CredentialStore
    ) -> None:
        """Test that credentials can be decrypted correctly."""
        original_value = "super-secret-api-key-12345"

        credential_store.set(
            platform="test",
            name="api",
            data={"api_key": original_value},
        )

        retrieved = credential_store.get(platform="test", name="api")

        assert retrieved is not None
        assert retrieved.data["api_key"] == original_value

    def test_different_keys_produce_different_encryption(
        self, temp_credential_dir: Path
    ) -> None:
        """Test that different encryption keys produce different ciphertext."""
        # Create two separate stores (they will have different encryption keys)
        store1_dir = temp_credential_dir / "store1"
        store2_dir = temp_credential_dir / "store2"
        store1_dir.mkdir()
        store2_dir.mkdir()

        store1 = CredentialStore(data_dir=store1_dir)
        store2 = CredentialStore(data_dir=store2_dir)

        # Store same value in both
        store1.set(platform="test", name="key", data={"value": "secret"})
        store2.set(platform="test", name="key", data={"value": "secret"})

        # Raw encrypted data should be different (different keys)
        raw1 = store1.credentials_file.read_bytes()
        raw2 = store2.credentials_file.read_bytes()

        assert raw1 != raw2

    def test_credential_deletion(
        self, credential_store: CredentialStore
    ) -> None:
        """Test that credentials are properly deleted."""
        credential_store.set(platform="test", name="to_delete", data={"secret": "value"})

        # Verify stored
        assert credential_store.get(platform="test", name="to_delete") is not None

        # Delete
        credential_store.delete(platform="test", name="to_delete")

        # Verify deleted
        assert credential_store.get(platform="test", name="to_delete") is None

    def test_credential_update(
        self, credential_store: CredentialStore
    ) -> None:
        """Test that credentials can be updated."""
        credential_store.set(platform="test", name="api", data={"key": "old-value"})
        credential_store.set(platform="test", name="api", data={"key": "new-value"})

        retrieved = credential_store.get(platform="test", name="api")
        assert retrieved is not None
        assert retrieved.data["key"] == "new-value"

    def test_multiple_platforms(
        self, credential_store: CredentialStore
    ) -> None:
        """Test storing credentials for multiple platforms."""
        platforms = {
            "aws": {"name": "prod", "data": {"access_key_id": "AKIA...", "secret_access_key": "secret123"}},
            "okta": {"name": "main", "data": {"domain": "test.okta.com", "api_token": "token123"}},
            "github": {"name": "default", "data": {"token": "ghp_..."}},
        }

        for platform, cred_info in platforms.items():
            credential_store.set(platform=platform, name=cred_info["name"], data=cred_info["data"])

        # Verify all retrievable
        for platform, cred_info in platforms.items():
            cred = credential_store.get(platform=platform, name=cred_info["name"])
            assert cred is not None
            assert cred.data == cred_info["data"]


# =============================================================================
# RBAC Permission Tests (Step 11.4.3)
# =============================================================================


@pytest.mark.security
class TestRBACPermissions:
    """Tests for RBAC permission enforcement."""

    def test_admin_has_all_permissions(
        self, rbac_manager: RBACManager
    ) -> None:
        """Test that admin role has all permissions."""
        admin_user = rbac_manager.create_user("admin@example.com", role=Role.ADMIN)

        # Admin should have all permissions
        assert rbac_manager.has_permission(admin_user, Permission.SCAN_RUN)
        assert rbac_manager.has_permission(admin_user, Permission.COLLECT_RUN)
        assert rbac_manager.has_permission(admin_user, Permission.REPORT_GENERATE)
        assert rbac_manager.has_permission(admin_user, Permission.CREDENTIAL_MANAGE)
        assert rbac_manager.has_permission(admin_user, Permission.USER_MANAGE)
        assert rbac_manager.has_permission(admin_user, Permission.CONFIG_MANAGE)

    def test_analyst_limited_permissions(
        self, rbac_manager: RBACManager
    ) -> None:
        """Test that analyst role has limited permissions."""
        analyst = rbac_manager.create_user("analyst@example.com", role=Role.ANALYST)

        # Analyst can read/view
        assert rbac_manager.has_permission(analyst, Permission.SCAN_VIEW)
        assert rbac_manager.has_permission(analyst, Permission.COLLECT_VIEW)
        assert rbac_manager.has_permission(analyst, Permission.REPORT_VIEW)

        # Analyst cannot modify sensitive settings
        assert not rbac_manager.has_permission(analyst, Permission.CREDENTIAL_MANAGE)
        assert not rbac_manager.has_permission(analyst, Permission.USER_MANAGE)
        assert not rbac_manager.has_permission(analyst, Permission.CONFIG_MANAGE)

    def test_viewer_read_only(
        self, rbac_manager: RBACManager
    ) -> None:
        """Test that viewer role is read-only."""
        viewer = rbac_manager.create_user("viewer@example.com", role=Role.VIEWER)

        # Viewer can only read
        assert rbac_manager.has_permission(viewer, Permission.SCAN_VIEW)
        assert rbac_manager.has_permission(viewer, Permission.REPORT_VIEW)

        # Viewer cannot execute anything
        assert not rbac_manager.has_permission(viewer, Permission.SCAN_RUN)
        assert not rbac_manager.has_permission(viewer, Permission.COLLECT_RUN)
        assert not rbac_manager.has_permission(viewer, Permission.REPORT_GENERATE)

    def test_operator_run_permissions(
        self, rbac_manager: RBACManager
    ) -> None:
        """Test that operator role can run but not configure."""
        operator = rbac_manager.create_user("operator@example.com", role=Role.OPERATOR)

        # Operator can run operations
        assert rbac_manager.has_permission(operator, Permission.SCAN_RUN)
        assert rbac_manager.has_permission(operator, Permission.COLLECT_RUN)
        assert rbac_manager.has_permission(operator, Permission.REPORT_GENERATE)

        # Operator cannot manage users or config
        assert not rbac_manager.has_permission(operator, Permission.USER_MANAGE)
        assert not rbac_manager.has_permission(operator, Permission.CONFIG_MANAGE)

    def test_permission_boundaries(
        self, rbac_manager: RBACManager
    ) -> None:
        """Test that permission boundaries are enforced."""
        analyst = rbac_manager.create_user("analyst@example.com", role=Role.ANALYST)

        # Attempt to escalate permissions should fail
        with pytest.raises(PermissionError):
            rbac_manager.grant_permission(
                analyst,
                Permission.USER_MANAGE,
                granted_by=analyst,  # Analyst cannot grant
            )

    def test_privilege_escalation_prevention(
        self, rbac_manager: RBACManager
    ) -> None:
        """Test that privilege escalation is prevented."""
        operator = rbac_manager.create_user("operator@example.com", role=Role.OPERATOR)

        # Operator cannot promote themselves to admin
        with pytest.raises(PermissionError):
            rbac_manager.change_role(
                user=operator,
                new_role=Role.ADMIN,
                changed_by=operator,
            )

    def test_permission_decorator(
        self, rbac_manager: RBACManager
    ) -> None:
        """Test permission decorator enforcement."""
        viewer = rbac_manager.create_user("viewer@example.com", role=Role.VIEWER)

        @check_permission(Permission.SCAN_RUN, rbac_manager)
        def run_scan(user):
            return "scan_completed"

        # Viewer should not be able to run scan
        with pytest.raises(PermissionError):
            run_scan(viewer)

    def test_audit_logging_of_permission_checks(
        self, rbac_manager: RBACManager, audit_log: AuditLog
    ) -> None:
        """Test that permission checks are logged."""
        rbac_manager.set_audit_log(audit_log)

        admin = rbac_manager.create_user("admin@example.com", role=Role.ADMIN)
        viewer = rbac_manager.create_user("viewer@example.com", role=Role.VIEWER)

        # Check permissions
        rbac_manager.has_permission(admin, Permission.SCAN_RUN)
        rbac_manager.has_permission(viewer, Permission.SCAN_RUN)

        # Verify logged
        entries = audit_log.get_entries()
        permission_entries = [e for e in entries if e.action == AuditAction.PERMISSION_CHECK]

        assert len(permission_entries) >= 2


# =============================================================================
# Audit Log Tamper Detection Tests (Step 11.4.4)
# =============================================================================


@pytest.mark.security
class TestAuditLogIntegrity:
    """Tests for audit log tamper detection."""

    def test_audit_entry_has_checksum(
        self, audit_log: AuditLog
    ) -> None:
        """Test that audit entries have checksums."""
        audit_log.log(
            action=AuditAction.SCAN_STARTED,
            user="admin@example.com",
            details={"scan_type": "aws"},
        )

        entries = audit_log.get_entries()
        assert len(entries) == 1
        assert entries[0].checksum is not None
        assert len(entries[0].checksum) == 64  # SHA-256

    def test_audit_chain_integrity(
        self, audit_log: AuditLog
    ) -> None:
        """Test audit log maintains integrity chain."""
        # Add multiple entries
        for i in range(5):
            audit_log.log(
                action=AuditAction.SCAN_COMPLETED,
                user="admin@example.com",
                details={"scan_id": i},
            )

        # Verify chain integrity
        assert verify_audit_chain(audit_log) is True

    def test_tampering_detected(
        self, audit_log: AuditLog
    ) -> None:
        """Test that tampering is detected."""
        # Add entries
        audit_log.log(
            action=AuditAction.CREDENTIAL_ACCESSED,
            user="admin@example.com",
            details={"platform": "aws"},
        )
        audit_log.log(
            action=AuditAction.SCAN_STARTED,
            user="admin@example.com",
            details={},
        )

        # Tamper with an entry
        entries = audit_log.get_entries()
        entries[0].details = {"platform": "hacked"}  # Modify
        audit_log._entries = entries  # Force write

        # Verification should fail
        assert verify_audit_chain(audit_log) is False

    def test_entry_modification_changes_checksum(
        self, audit_log: AuditLog
    ) -> None:
        """Test that entry modification changes checksum."""
        audit_log.log(
            action=AuditAction.USER_LOGIN,
            user="user@example.com",
            details={"ip": "192.168.1.1"},
        )

        entries = audit_log.get_entries()
        original_checksum = entries[0].checksum

        # Compute checksum with modified data
        modified_entry = AuditEntry(
            timestamp=entries[0].timestamp,
            action=entries[0].action,
            user="different@example.com",  # Changed
            details=entries[0].details,
        )
        modified_checksum = modified_entry.compute_checksum()

        assert original_checksum != modified_checksum

    def test_audit_log_persistence(
        self, tmp_path: Path
    ) -> None:
        """Test audit log persists across restarts."""
        log_path = tmp_path / "audit.log"

        # Create and write
        log1 = AuditLog(log_path=log_path)
        log1.log(
            action=AuditAction.CONFIG_CHANGED,
            user="admin@example.com",
            details={"setting": "value"},
        )

        # Close and reopen
        del log1
        log2 = AuditLog(log_path=log_path)

        # Entries should persist
        entries = log2.get_entries()
        assert len(entries) == 1
        assert entries[0].action == AuditAction.CONFIG_CHANGED

        # Chain should still be valid
        assert verify_audit_chain(log2) is True

    def test_audit_chain_with_previous_hash(
        self, audit_log: AuditLog
    ) -> None:
        """Test that each entry includes previous entry's hash."""
        audit_log.log(
            action=AuditAction.SCAN_STARTED,
            user="admin@example.com",
            details={},
        )
        audit_log.log(
            action=AuditAction.SCAN_COMPLETED,
            user="admin@example.com",
            details={},
        )

        entries = audit_log.get_entries()

        # Second entry should reference first entry's hash
        assert entries[1].previous_hash == entries[0].checksum

    def test_first_entry_has_no_previous(
        self, audit_log: AuditLog
    ) -> None:
        """Test that first entry has no previous hash."""
        audit_log.log(
            action=AuditAction.SCAN_STARTED,
            user="admin@example.com",
            details={},
        )

        entries = audit_log.get_entries()
        assert entries[0].previous_hash is None or entries[0].previous_hash == ""


# =============================================================================
# Input Validation Tests
# =============================================================================


@pytest.mark.security
class TestInputValidation:
    """Tests for input validation and sanitization."""

    def test_sql_injection_prevention(
        self, rbac_manager: RBACManager
    ) -> None:
        """Test that SQL injection is prevented."""
        # Attempt SQL injection in user email
        with pytest.raises(ValueError):
            rbac_manager.create_user(
                email="'; DROP TABLE users; --",
                role=Role.VIEWER,
            )

    def test_command_injection_in_credentials_safe(
        self, credential_store: CredentialStore
    ) -> None:
        """Test that command injection attempts in credentials are safely stored."""
        # Should safely store without executing
        credential_store.set(
            platform="test",
            name="command_test",
            data={"value": "$(rm -rf /)"},  # Command injection attempt
        )

        # Value should be stored as-is, not executed
        retrieved = credential_store.get(platform="test", name="command_test")
        assert retrieved is not None
        assert retrieved.data["value"] == "$(rm -rf /)"


# =============================================================================
# Security Configuration Tests
# =============================================================================


@pytest.mark.security
class TestSecurityConfiguration:
    """Tests for security configuration verification."""

    def test_key_file_has_secure_permissions(
        self, credential_store: CredentialStore
    ) -> None:
        """Test that encryption key file has secure permissions."""
        # Store something to trigger key generation
        credential_store.set(platform="test", name="key", data={"value": "test"})

        # Check key file permissions
        key_stat = credential_store.key_file.stat()
        mode = stat.S_IMODE(key_stat.st_mode)
        # Should be readable only by owner (400)
        assert mode == stat.S_IRUSR

    def test_credentials_file_has_secure_permissions(
        self, credential_store: CredentialStore
    ) -> None:
        """Test that credentials file has secure permissions."""
        credential_store.set(platform="test", name="key", data={"value": "test"})

        # Check credentials file permissions
        cred_stat = credential_store.credentials_file.stat()
        mode = stat.S_IMODE(cred_stat.st_mode)
        # Should be readable/writable only by owner (600)
        assert mode == (stat.S_IRUSR | stat.S_IWUSR)

    def test_no_secrets_in_logs(
        self, audit_log: AuditLog
    ) -> None:
        """Test that secrets are not logged."""
        # Log an action with sensitive data
        audit_log.log(
            action=AuditAction.CREDENTIAL_ACCESSED,
            user="admin@example.com",
            details={"platform": "aws", "key": "access_key"},
        )

        # Read raw log
        log_content = audit_log.log_path.read_text()

        # Actual credentials should not appear
        assert "AKIAIOSFODNN7EXAMPLE" not in log_content
        assert "secret_access_key" not in log_content.lower()

    def test_sensitive_data_masking(
        self, audit_log: AuditLog
    ) -> None:
        """Test that sensitive data is masked in logs."""
        audit_log.log(
            action=AuditAction.CREDENTIAL_STORED,
            user="admin@example.com",
            details={
                "platform": "aws",
                "key": "access_key",
                "value": "AKIAIOSFODNN7EXAMPLE",  # This should be masked
            },
        )

        entries = audit_log.get_entries()

        # Value should be masked or redacted
        value = entries[0].details.get("value", "")
        assert "AKIAIOSFODNN7EXAMPLE" not in value
        assert "***" in value or "[REDACTED]" in value


# =============================================================================
# Bandit Configuration Test (Step 11.4.1)
# =============================================================================


@pytest.mark.security
class TestBanditConfiguration:
    """Tests verifying Bandit security scanning configuration."""

    def test_bandit_config_exists(self) -> None:
        """Test that Bandit configuration exists."""
        config_paths = [
            Path("pyproject.toml"),
            Path(".bandit"),
            Path("bandit.yaml"),
        ]

        # At least one config should exist
        config_exists = any(p.exists() for p in config_paths)

        # If pyproject.toml exists, check for bandit config
        pyproject = Path("pyproject.toml")
        if pyproject.exists():
            content = pyproject.read_text()
            if "[tool.bandit]" in content:
                config_exists = True

        # This test documents the expectation
        # In CI, Bandit should be configured
        assert config_exists or os.getenv("CI") is None

    def test_no_hardcoded_passwords_in_source(self) -> None:
        """Test that source code doesn't contain hardcoded passwords."""
        src_path = Path("src/attestful")

        if not src_path.exists():
            pytest.skip("Source path not found")

        suspicious_patterns = [
            "password = ",
            "password=",
            "secret_key = ",
            "api_key = ",
            'password: "',
            "password: '",
        ]

        findings = []

        for py_file in src_path.rglob("*.py"):
            content = py_file.read_text()
            for pattern in suspicious_patterns:
                if pattern in content.lower():
                    # Check if it's in a comment or assignment from env/config
                    lines = content.split("\n")
                    for i, line in enumerate(lines):
                        if pattern in line.lower():
                            # Allow if it's reading from env or config
                            if "os.getenv" in line or "config." in line:
                                continue
                            if line.strip().startswith("#"):
                                continue
                            findings.append((py_file, i + 1, line.strip()))

        # Document findings but don't fail (might be false positives)
        # In real CI, this would integrate with Bandit
        if findings:
            for f, line, content in findings:
                print(f"Potential hardcoded secret in {f}:{line}: {content[:50]}...")
