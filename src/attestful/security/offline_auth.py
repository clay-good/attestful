"""
Offline authentication and credential validation for Attestful.

Provides authentication result caching, token refresh management,
and offline validation for air-gapped deployments.

Features:
- Cache successful authentication results
- Automatic token refresh before expiry
- Offline token validation where possible
- Graceful handling of expired credentials
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, TypeVar

from cryptography.fernet import Fernet, InvalidToken

from attestful.core.exceptions import SecurityError
from attestful.core.logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


class AuthStatus(str, Enum):
    """Authentication status values."""

    VALID = "valid"
    EXPIRED = "expired"
    EXPIRING_SOON = "expiring_soon"
    REFRESH_REQUIRED = "refresh_required"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class TokenType(str, Enum):
    """Supported token types."""

    API_KEY = "api_key"
    OAUTH_ACCESS = "oauth_access"
    OAUTH_REFRESH = "oauth_refresh"
    JWT = "jwt"
    SESSION = "session"
    SERVICE_ACCOUNT = "service_account"
    BASIC = "basic"


@dataclass
class CachedAuthResult:
    """
    Cached authentication result.

    Stores the result of a successful authentication along with
    expiration information for offline validation.
    """

    platform: str
    credential_name: str
    token_type: TokenType
    authenticated_at: datetime
    expires_at: datetime | None = None
    refresh_at: datetime | None = None
    scopes: list[str] = field(default_factory=list)
    identity: dict[str, Any] = field(default_factory=dict)
    access_token_hash: str | None = None
    refresh_token_hash: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if the authentication has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def is_expiring_soon(self, threshold_minutes: int = 15) -> bool:
        """Check if expiring within threshold."""
        if self.expires_at is None:
            return False
        threshold = timedelta(minutes=threshold_minutes)
        return datetime.now(timezone.utc) > (self.expires_at - threshold)

    def needs_refresh(self) -> bool:
        """Check if token should be refreshed."""
        if self.refresh_at is not None:
            return datetime.now(timezone.utc) > self.refresh_at
        return self.is_expiring_soon()

    def get_status(self) -> AuthStatus:
        """Get current authentication status."""
        if self.is_expired():
            return AuthStatus.EXPIRED
        if self.needs_refresh():
            return AuthStatus.REFRESH_REQUIRED
        if self.is_expiring_soon():
            return AuthStatus.EXPIRING_SOON
        return AuthStatus.VALID

    def time_until_expiry(self) -> timedelta | None:
        """Get time remaining until expiry."""
        if self.expires_at is None:
            return None
        return self.expires_at - datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "platform": self.platform,
            "credential_name": self.credential_name,
            "token_type": self.token_type.value,
            "authenticated_at": self.authenticated_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "refresh_at": self.refresh_at.isoformat() if self.refresh_at else None,
            "scopes": self.scopes,
            "identity": self.identity,
            "access_token_hash": self.access_token_hash,
            "refresh_token_hash": self.refresh_token_hash,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CachedAuthResult:
        """Create from dictionary."""
        return cls(
            platform=data["platform"],
            credential_name=data["credential_name"],
            token_type=TokenType(data["token_type"]),
            authenticated_at=datetime.fromisoformat(data["authenticated_at"]),
            expires_at=(
                datetime.fromisoformat(data["expires_at"])
                if data.get("expires_at") else None
            ),
            refresh_at=(
                datetime.fromisoformat(data["refresh_at"])
                if data.get("refresh_at") else None
            ),
            scopes=data.get("scopes", []),
            identity=data.get("identity", {}),
            access_token_hash=data.get("access_token_hash"),
            refresh_token_hash=data.get("refresh_token_hash"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ValidationResult:
    """Result of offline credential validation."""

    is_valid: bool
    status: AuthStatus
    message: str
    cached_result: CachedAuthResult | None = None
    needs_online_refresh: bool = False
    suggested_action: str | None = None

    @classmethod
    def valid(
        cls,
        cached_result: CachedAuthResult,
        message: str = "Credential validated from cache",
    ) -> ValidationResult:
        """Create a valid result."""
        return cls(
            is_valid=True,
            status=AuthStatus.VALID,
            message=message,
            cached_result=cached_result,
        )

    @classmethod
    def expired(
        cls,
        cached_result: CachedAuthResult | None = None,
        message: str = "Credential has expired",
    ) -> ValidationResult:
        """Create an expired result."""
        return cls(
            is_valid=False,
            status=AuthStatus.EXPIRED,
            message=message,
            cached_result=cached_result,
            needs_online_refresh=True,
            suggested_action="Re-authenticate when network is available",
        )

    @classmethod
    def needs_refresh(
        cls,
        cached_result: CachedAuthResult,
        message: str = "Credential needs refresh",
    ) -> ValidationResult:
        """Create a needs-refresh result."""
        return cls(
            is_valid=True,  # Still valid but should refresh
            status=AuthStatus.REFRESH_REQUIRED,
            message=message,
            cached_result=cached_result,
            needs_online_refresh=True,
            suggested_action="Refresh token when network is available",
        )

    @classmethod
    def not_found(cls, platform: str, name: str) -> ValidationResult:
        """Create a not-found result."""
        return cls(
            is_valid=False,
            status=AuthStatus.UNKNOWN,
            message=f"No cached authentication for {platform}/{name}",
            needs_online_refresh=True,
            suggested_action="Authenticate online first",
        )


class OfflineAuthCache:
    """
    Manages cached authentication results for offline validation.

    Stores encrypted authentication results that can be validated
    without network access. Supports automatic token refresh when
    online connectivity is available.

    Example:
        cache = OfflineAuthCache(data_dir=Path("~/.attestful"))

        # Cache successful auth
        cache.cache_authentication(
            platform="okta",
            credential_name="production",
            token_type=TokenType.OAUTH_ACCESS,
            expires_in_seconds=3600,
            identity={"email": "user@example.com"},
        )

        # Validate offline
        result = cache.validate_offline("okta", "production")
        if result.is_valid:
            print("Valid until:", result.cached_result.expires_at)
    """

    # Default cache file name
    CACHE_FILE = "auth_cache.enc"

    # How long to trust cached auth without re-validation (days)
    DEFAULT_MAX_CACHE_AGE_DAYS = 30

    # Grace period for expiring tokens (minutes)
    DEFAULT_EXPIRY_GRACE_MINUTES = 15

    def __init__(
        self,
        data_dir: Path | None = None,
        cache_file: Path | None = None,
        encryption_key: bytes | None = None,
        max_cache_age_days: int = DEFAULT_MAX_CACHE_AGE_DAYS,
        expiry_grace_minutes: int = DEFAULT_EXPIRY_GRACE_MINUTES,
    ) -> None:
        """
        Initialize offline auth cache.

        Args:
            data_dir: Base directory for cache storage.
            cache_file: Path to cache file (overrides data_dir).
            encryption_key: Fernet encryption key for cache.
            max_cache_age_days: Maximum age for cached auth.
            expiry_grace_minutes: Grace period before expiry.
        """
        self.data_dir = data_dir or Path.home() / ".attestful"
        self.cache_file = cache_file or (self.data_dir / self.CACHE_FILE)
        self.max_cache_age = timedelta(days=max_cache_age_days)
        self.expiry_grace = timedelta(minutes=expiry_grace_minutes)

        self._encryption_key = encryption_key
        self._fernet: Fernet | None = None
        self._cache: dict[str, CachedAuthResult] = {}
        self._loaded = False

    def _make_cache_key(self, platform: str, credential_name: str) -> str:
        """Create unique cache key for platform/credential."""
        return f"{platform}:{credential_name}"

    def _get_fernet(self) -> Fernet:
        """Get or create Fernet encryption instance."""
        if self._fernet is not None:
            return self._fernet

        if self._encryption_key is not None:
            self._fernet = Fernet(self._encryption_key)
        else:
            # Try to get key from credential store
            key_file = self.data_dir / ".key"
            if key_file.exists():
                self._fernet = Fernet(key_file.read_bytes())
            else:
                raise SecurityError(
                    "No encryption key available for auth cache",
                    details={"key_file": str(key_file)},
                )

        return self._fernet

    def _load(self) -> None:
        """Load cache from encrypted file."""
        if self._loaded:
            return

        self._cache = {}

        if not self.cache_file.exists():
            self._loaded = True
            return

        try:
            encrypted_data = self.cache_file.read_bytes()
            fernet = self._get_fernet()
            decrypted_data = fernet.decrypt(encrypted_data)
            raw_cache = json.loads(decrypted_data.decode("utf-8"))

            for key, data in raw_cache.items():
                try:
                    self._cache[key] = CachedAuthResult.from_dict(data)
                except (KeyError, ValueError) as e:
                    logger.warning(f"Skipping invalid cache entry {key}: {e}")

            logger.debug(f"Loaded {len(self._cache)} cached auth results")
            self._loaded = True

        except InvalidToken:
            logger.warning("Failed to decrypt auth cache, starting fresh")
            self._loaded = True
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid auth cache format: {e}")
            self._loaded = True

    def _save(self) -> None:
        """Save cache to encrypted file."""
        self.data_dir.mkdir(parents=True, exist_ok=True)

        raw_cache = {
            key: result.to_dict()
            for key, result in self._cache.items()
        }

        json_data = json.dumps(raw_cache, indent=2)
        fernet = self._get_fernet()
        encrypted_data = fernet.encrypt(json_data.encode("utf-8"))

        self.cache_file.write_bytes(encrypted_data)
        logger.debug(f"Saved {len(self._cache)} cached auth results")

    @staticmethod
    def hash_token(token: str) -> str:
        """
        Create a secure hash of a token for verification.

        Uses HMAC with SHA-256 and a fixed internal key.
        The hash can be used to verify token authenticity
        without storing the actual token.
        """
        # Use a fixed internal key - not for security, just consistency
        key = b"attestful-token-hash-key-v1"
        return hmac.new(key, token.encode(), hashlib.sha256).hexdigest()

    def cache_authentication(
        self,
        platform: str,
        credential_name: str,
        token_type: TokenType,
        expires_in_seconds: int | None = None,
        refresh_in_seconds: int | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        scopes: list[str] | None = None,
        identity: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CachedAuthResult:
        """
        Cache a successful authentication result.

        Args:
            platform: Platform identifier.
            credential_name: Credential name/alias.
            token_type: Type of authentication token.
            expires_in_seconds: Token expiration in seconds.
            refresh_in_seconds: When to refresh (defaults to 80% of expiry).
            access_token: Access token to hash for verification.
            refresh_token: Refresh token to hash for verification.
            scopes: OAuth scopes granted.
            identity: User/service identity information.
            metadata: Additional metadata.

        Returns:
            The cached authentication result.
        """
        self._load()

        now = datetime.now(timezone.utc)

        # Calculate expiry and refresh times
        expires_at = None
        refresh_at = None

        if expires_in_seconds is not None:
            expires_at = now + timedelta(seconds=expires_in_seconds)

            if refresh_in_seconds is not None:
                refresh_at = now + timedelta(seconds=refresh_in_seconds)
            else:
                # Default: refresh at 80% of token lifetime
                refresh_at = now + timedelta(seconds=int(expires_in_seconds * 0.8))

        # Hash tokens for verification (don't store actual tokens)
        access_token_hash = self.hash_token(access_token) if access_token else None
        refresh_token_hash = self.hash_token(refresh_token) if refresh_token else None

        result = CachedAuthResult(
            platform=platform,
            credential_name=credential_name,
            token_type=token_type,
            authenticated_at=now,
            expires_at=expires_at,
            refresh_at=refresh_at,
            scopes=scopes or [],
            identity=identity or {},
            access_token_hash=access_token_hash,
            refresh_token_hash=refresh_token_hash,
            metadata=metadata or {},
        )

        cache_key = self._make_cache_key(platform, credential_name)
        self._cache[cache_key] = result
        self._save()

        logger.info(
            f"Cached authentication for {platform}/{credential_name}",
            extra={
                "expires_at": expires_at.isoformat() if expires_at else None,
                "token_type": token_type.value,
            },
        )

        return result

    def validate_offline(
        self,
        platform: str,
        credential_name: str,
        current_token: str | None = None,
    ) -> ValidationResult:
        """
        Validate a credential offline using cached authentication.

        Args:
            platform: Platform identifier.
            credential_name: Credential name.
            current_token: Current token to verify against cache.

        Returns:
            Validation result with status and recommendations.
        """
        self._load()

        cache_key = self._make_cache_key(platform, credential_name)
        cached = self._cache.get(cache_key)

        if cached is None:
            return ValidationResult.not_found(platform, credential_name)

        # Check if cache is too old
        cache_age = datetime.now(timezone.utc) - cached.authenticated_at
        if cache_age > self.max_cache_age:
            return ValidationResult(
                is_valid=False,
                status=AuthStatus.EXPIRED,
                message=f"Cached authentication is too old ({cache_age.days} days)",
                cached_result=cached,
                needs_online_refresh=True,
                suggested_action="Re-authenticate to refresh cache",
            )

        # Verify token hash if provided
        if current_token and cached.access_token_hash:
            current_hash = self.hash_token(current_token)
            if current_hash != cached.access_token_hash:
                return ValidationResult(
                    is_valid=False,
                    status=AuthStatus.INVALID,
                    message="Token does not match cached authentication",
                    cached_result=cached,
                    needs_online_refresh=True,
                    suggested_action="Re-authenticate with new token",
                )

        # Check expiration
        if cached.is_expired():
            return ValidationResult.expired(cached)

        # Check if refresh needed
        if cached.needs_refresh():
            return ValidationResult.needs_refresh(cached)

        # Valid with possible warning about expiring soon
        if cached.is_expiring_soon(threshold_minutes=int(self.expiry_grace.total_seconds() / 60)):
            remaining = cached.time_until_expiry()
            return ValidationResult(
                is_valid=True,
                status=AuthStatus.EXPIRING_SOON,
                message=f"Credential expires in {remaining}",
                cached_result=cached,
                needs_online_refresh=True,
                suggested_action="Refresh soon when network available",
            )

        return ValidationResult.valid(cached)

    def get_cached_auth(
        self,
        platform: str,
        credential_name: str,
    ) -> CachedAuthResult | None:
        """
        Get cached authentication result.

        Args:
            platform: Platform identifier.
            credential_name: Credential name.

        Returns:
            Cached result if found, None otherwise.
        """
        self._load()
        cache_key = self._make_cache_key(platform, credential_name)
        return self._cache.get(cache_key)

    def invalidate(self, platform: str, credential_name: str) -> bool:
        """
        Invalidate cached authentication.

        Args:
            platform: Platform identifier.
            credential_name: Credential name.

        Returns:
            True if cache was invalidated, False if not found.
        """
        self._load()

        cache_key = self._make_cache_key(platform, credential_name)
        if cache_key not in self._cache:
            return False

        del self._cache[cache_key]
        self._save()

        logger.info(f"Invalidated cached auth for {platform}/{credential_name}")
        return True

    def invalidate_platform(self, platform: str) -> int:
        """
        Invalidate all cached authentications for a platform.

        Args:
            platform: Platform identifier.

        Returns:
            Number of entries invalidated.
        """
        self._load()

        prefix = f"{platform}:"
        keys_to_remove = [k for k in self._cache if k.startswith(prefix)]

        for key in keys_to_remove:
            del self._cache[key]

        if keys_to_remove:
            self._save()
            logger.info(f"Invalidated {len(keys_to_remove)} cached auth entries for {platform}")

        return len(keys_to_remove)

    def cleanup_expired(self) -> int:
        """
        Remove expired entries from cache.

        Returns:
            Number of entries removed.
        """
        self._load()

        now = datetime.now(timezone.utc)
        keys_to_remove = []

        for key, cached in self._cache.items():
            # Remove if expired or too old
            if cached.is_expired():
                keys_to_remove.append(key)
            elif (now - cached.authenticated_at) > self.max_cache_age:
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self._cache[key]

        if keys_to_remove:
            self._save()
            logger.info(f"Cleaned up {len(keys_to_remove)} expired auth cache entries")

        return len(keys_to_remove)

    def list_cached(self) -> list[dict[str, Any]]:
        """
        List all cached authentications with status.

        Returns:
            List of cache entry summaries.
        """
        self._load()

        result = []
        for key, cached in self._cache.items():
            result.append({
                "platform": cached.platform,
                "credential_name": cached.credential_name,
                "token_type": cached.token_type.value,
                "status": cached.get_status().value,
                "authenticated_at": cached.authenticated_at.isoformat(),
                "expires_at": cached.expires_at.isoformat() if cached.expires_at else None,
                "identity": cached.identity,
            })

        return sorted(result, key=lambda x: (x["platform"], x["credential_name"]))

    def export_for_offline(self, output_path: Path) -> int:
        """
        Export cache for offline deployment.

        Args:
            output_path: Path to write encrypted cache.

        Returns:
            Number of entries exported.
        """
        self._load()

        # Only export non-expired entries
        valid_entries = {
            key: result.to_dict()
            for key, result in self._cache.items()
            if not result.is_expired()
        }

        json_data = json.dumps(valid_entries, indent=2)
        fernet = self._get_fernet()
        encrypted_data = fernet.encrypt(json_data.encode("utf-8"))

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(encrypted_data)

        logger.info(f"Exported {len(valid_entries)} auth cache entries to {output_path}")
        return len(valid_entries)

    def import_from_offline(
        self,
        input_path: Path,
        merge: bool = True,
    ) -> int:
        """
        Import cache from offline export.

        Args:
            input_path: Path to encrypted cache file.
            merge: If True, merge with existing cache. If False, replace.

        Returns:
            Number of entries imported.
        """
        if not input_path.exists():
            raise SecurityError(
                "Auth cache file not found",
                details={"path": str(input_path)},
            )

        encrypted_data = input_path.read_bytes()
        fernet = self._get_fernet()

        try:
            decrypted_data = fernet.decrypt(encrypted_data)
        except InvalidToken:
            raise SecurityError(
                "Failed to decrypt auth cache - key mismatch",
                details={"path": str(input_path)},
            )

        raw_cache = json.loads(decrypted_data.decode("utf-8"))

        if merge:
            self._load()
        else:
            self._cache = {}
            self._loaded = True

        imported_count = 0
        for key, data in raw_cache.items():
            try:
                result = CachedAuthResult.from_dict(data)
                # Skip expired entries
                if not result.is_expired():
                    self._cache[key] = result
                    imported_count += 1
            except (KeyError, ValueError) as e:
                logger.warning(f"Skipping invalid cache entry {key}: {e}")

        self._save()
        logger.info(f"Imported {imported_count} auth cache entries from {input_path}")

        return imported_count


class TokenRefreshManager:
    """
    Manages automatic token refresh for OAuth and similar auth systems.

    Tracks tokens that need refresh and coordinates refresh operations
    when network connectivity is available.
    """

    def __init__(
        self,
        auth_cache: OfflineAuthCache | None = None,
        refresh_threshold_minutes: int = 15,
    ) -> None:
        """
        Initialize token refresh manager.

        Args:
            auth_cache: Offline auth cache to manage.
            refresh_threshold_minutes: Refresh tokens this many minutes before expiry.
        """
        self._auth_cache = auth_cache
        self._refresh_threshold = timedelta(minutes=refresh_threshold_minutes)
        self._refresh_handlers: dict[str, Callable[[CachedAuthResult], CachedAuthResult | None]] = {}

    @property
    def auth_cache(self) -> OfflineAuthCache:
        """Get the auth cache (lazy init if needed)."""
        if self._auth_cache is None:
            self._auth_cache = get_offline_auth_cache()
        return self._auth_cache

    def register_refresh_handler(
        self,
        platform: str,
        handler: Callable[[CachedAuthResult], CachedAuthResult | None],
    ) -> None:
        """
        Register a refresh handler for a platform.

        The handler receives the cached auth result and should return
        a new CachedAuthResult if refresh was successful, or None if
        refresh failed.

        Args:
            platform: Platform identifier.
            handler: Refresh callback function.
        """
        self._refresh_handlers[platform] = handler
        logger.debug(f"Registered refresh handler for {platform}")

    def get_tokens_needing_refresh(self) -> list[CachedAuthResult]:
        """
        Get all tokens that need refresh.

        Returns:
            List of cached auth results needing refresh.
        """
        cached_list = self.auth_cache.list_cached()
        needing_refresh = []

        for entry in cached_list:
            if entry["status"] in (
                AuthStatus.REFRESH_REQUIRED.value,
                AuthStatus.EXPIRING_SOON.value,
            ):
                cached = self.auth_cache.get_cached_auth(
                    entry["platform"],
                    entry["credential_name"],
                )
                if cached:
                    needing_refresh.append(cached)

        return needing_refresh

    def refresh_token(self, cached: CachedAuthResult) -> tuple[bool, str]:
        """
        Attempt to refresh a single token.

        Args:
            cached: Cached auth result to refresh.

        Returns:
            Tuple of (success, message).
        """
        handler = self._refresh_handlers.get(cached.platform)
        if handler is None:
            return False, f"No refresh handler for platform: {cached.platform}"

        try:
            new_result = handler(cached)
            if new_result is not None:
                logger.info(
                    f"Refreshed token for {cached.platform}/{cached.credential_name}"
                )
                return True, "Token refreshed successfully"
            else:
                return False, "Refresh handler returned None"
        except Exception as e:
            logger.warning(
                f"Token refresh failed for {cached.platform}/{cached.credential_name}: {e}"
            )
            return False, f"Refresh failed: {e}"

    def refresh_all_pending(self) -> dict[str, list[tuple[str, bool, str]]]:
        """
        Attempt to refresh all tokens needing refresh.

        Returns:
            Dictionary mapping platforms to list of (credential_name, success, message).
        """
        results: dict[str, list[tuple[str, bool, str]]] = {}

        for cached in self.get_tokens_needing_refresh():
            if cached.platform not in results:
                results[cached.platform] = []

            success, message = self.refresh_token(cached)
            results[cached.platform].append((cached.credential_name, success, message))

        return results


class OfflineCredentialValidator:
    """
    Coordinates offline credential validation.

    Combines the credential store with auth cache to provide
    comprehensive offline validation capabilities.
    """

    def __init__(
        self,
        auth_cache: OfflineAuthCache | None = None,
    ) -> None:
        """
        Initialize offline credential validator.

        Args:
            auth_cache: Offline auth cache to use.
        """
        self._auth_cache = auth_cache

    @property
    def auth_cache(self) -> OfflineAuthCache:
        """Get auth cache (lazy init if needed)."""
        if self._auth_cache is None:
            self._auth_cache = get_offline_auth_cache()
        return self._auth_cache

    def validate_credential(
        self,
        platform: str,
        credential_name: str,
        require_cached_auth: bool = False,
    ) -> ValidationResult:
        """
        Validate a credential for offline use.

        Args:
            platform: Platform identifier.
            credential_name: Credential name.
            require_cached_auth: If True, require cached auth result.

        Returns:
            Validation result with recommendations.
        """
        from attestful.config.credentials import get_credential_store

        # First check if credential exists in store
        store = get_credential_store()
        credential = store.get(platform, credential_name)

        if credential is None:
            return ValidationResult(
                is_valid=False,
                status=AuthStatus.UNKNOWN,
                message=f"Credential not found: {platform}/{credential_name}",
                suggested_action="Add credential with 'attestful configure credentials'",
            )

        # Check cached authentication
        cached_result = self.auth_cache.validate_offline(platform, credential_name)

        if require_cached_auth and not cached_result.is_valid:
            return cached_result

        # If no cached auth but credential exists, it might still work
        if cached_result.status == AuthStatus.UNKNOWN:
            return ValidationResult(
                is_valid=True,  # Credential exists, might work
                status=AuthStatus.UNKNOWN,
                message="Credential exists but not validated offline",
                needs_online_refresh=True,
                suggested_action="Run online validation to cache auth result",
            )

        return cached_result

    def get_offline_status(self) -> dict[str, Any]:
        """
        Get overall offline credential status.

        Returns:
            Dictionary with status summary.
        """
        from attestful.config.credentials import get_credential_store

        store = get_credential_store()
        all_creds = store.list_all()

        cached_list = self.auth_cache.list_cached()
        cached_by_key = {
            f"{c['platform']}:{c['credential_name']}": c
            for c in cached_list
        }

        status_counts = {s.value: 0 for s in AuthStatus}
        credentials_status = []

        for platform, names in all_creds.items():
            for name in names:
                key = f"{platform}:{name}"
                cached = cached_by_key.get(key)

                if cached:
                    status = cached["status"]
                else:
                    status = AuthStatus.UNKNOWN.value

                status_counts[status] += 1
                credentials_status.append({
                    "platform": platform,
                    "name": name,
                    "status": status,
                    "expires_at": cached["expires_at"] if cached else None,
                })

        return {
            "total_credentials": sum(len(names) for names in all_creds.values()),
            "cached_authentications": len(cached_list),
            "status_counts": status_counts,
            "credentials": sorted(
                credentials_status,
                key=lambda x: (x["platform"], x["name"]),
            ),
        }


# Module-level singleton cache
_offline_auth_cache: OfflineAuthCache | None = None


def get_offline_auth_cache() -> OfflineAuthCache:
    """
    Get the offline auth cache singleton.

    Returns:
        OfflineAuthCache instance.
    """
    global _offline_auth_cache

    if _offline_auth_cache is None:
        from attestful.config.settings import get_settings

        settings = get_settings()
        _offline_auth_cache = OfflineAuthCache(
            data_dir=settings.data_dir,
        )

    return _offline_auth_cache


def reset_offline_auth_cache() -> None:
    """Reset the offline auth cache singleton (for testing)."""
    global _offline_auth_cache
    _offline_auth_cache = None
