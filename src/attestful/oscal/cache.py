"""
OSCAL Catalog and Profile Cache.

Provides persistent local caching for OSCAL documents to support offline
operation. Downloads catalogs on first use and stores them locally.

Features:
- Persistent disk cache in user data directory
- Automatic download from official NIST sources
- Cache invalidation based on timestamps
- Manual cache updates for air-gapped deployments
- Support for bundled catalogs
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from attestful.core.exceptions import CatalogError
from attestful.core.logging import get_logger

logger = get_logger("oscal.cache")


# =============================================================================
# Default OSCAL Catalog URLs
# =============================================================================

OFFICIAL_CATALOGS = {
    "nist-800-53-rev5": {
        "url": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
        "name": "NIST SP 800-53 Rev 5",
        "version": "5.0.0",
    },
    "nist-800-53-rev4": {
        "url": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev4/json/NIST_SP-800-53_rev4_catalog.json",
        "name": "NIST SP 800-53 Rev 4",
        "version": "4.0.0",
    },
    "fedramp-high": {
        "url": "https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_HIGH-baseline_profile.json",
        "name": "FedRAMP High Baseline",
        "version": "5.0.0",
        "type": "profile",
    },
    "fedramp-moderate": {
        "url": "https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline_profile.json",
        "name": "FedRAMP Moderate Baseline",
        "version": "5.0.0",
        "type": "profile",
    },
    "fedramp-low": {
        "url": "https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_LOW-baseline_profile.json",
        "name": "FedRAMP Low Baseline",
        "version": "5.0.0",
        "type": "profile",
    },
}

# Official FedRAMP profiles
OFFICIAL_PROFILES = {
    "fedramp-high": {
        "url": "https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_HIGH-baseline_profile.json",
        "name": "FedRAMP High Baseline",
        "version": "5.0.0",
        "catalog": "nist-800-53-rev5",
    },
    "fedramp-moderate": {
        "url": "https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline_profile.json",
        "name": "FedRAMP Moderate Baseline",
        "version": "5.0.0",
        "catalog": "nist-800-53-rev5",
    },
    "fedramp-low": {
        "url": "https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_LOW-baseline_profile.json",
        "name": "FedRAMP Low Baseline",
        "version": "5.0.0",
        "catalog": "nist-800-53-rev5",
    },
}

# Default cache directory
DEFAULT_CACHE_DIR = Path.home() / ".attestful" / "oscal_cache"

# Cache expiration (7 days by default)
DEFAULT_CACHE_TTL_DAYS = 7


@dataclass
class CacheEntry:
    """Metadata about a cached OSCAL document."""

    cache_id: str
    source_url: str | None = None
    source_path: str | None = None
    name: str = ""
    version: str = ""
    document_type: str = "catalog"  # catalog, profile, component, ssp
    content_hash: str = ""
    file_path: str = ""
    cached_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    size_bytes: int = 0
    is_bundled: bool = False  # True if from bundled content

    @property
    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "cache_id": self.cache_id,
            "source_url": self.source_url,
            "source_path": self.source_path,
            "name": self.name,
            "version": self.version,
            "document_type": self.document_type,
            "content_hash": self.content_hash,
            "file_path": self.file_path,
            "cached_at": self.cached_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "size_bytes": self.size_bytes,
            "is_bundled": self.is_bundled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CacheEntry:
        """Create from dictionary."""
        cached_at = data.get("cached_at")
        if isinstance(cached_at, str):
            cached_at = datetime.fromisoformat(cached_at.replace("Z", "+00:00"))
        else:
            cached_at = datetime.now(timezone.utc)

        expires_at = data.get("expires_at")
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        else:
            expires_at = None

        return cls(
            cache_id=data["cache_id"],
            source_url=data.get("source_url"),
            source_path=data.get("source_path"),
            name=data.get("name", ""),
            version=data.get("version", ""),
            document_type=data.get("document_type", "catalog"),
            content_hash=data.get("content_hash", ""),
            file_path=data.get("file_path", ""),
            cached_at=cached_at,
            expires_at=expires_at,
            size_bytes=data.get("size_bytes", 0),
            is_bundled=data.get("is_bundled", False),
        )


class OSCALCache:
    """
    Persistent cache for OSCAL documents.

    Stores catalogs, profiles, and other OSCAL documents locally
    to support offline operation.

    Example:
        cache = OSCALCache()

        # Download and cache NIST 800-53
        catalog_path = cache.get_catalog("nist-800-53-rev5")

        # Get from cache (no network needed)
        catalog_path = cache.get_catalog("nist-800-53-rev5")

        # Force refresh
        catalog_path = cache.get_catalog("nist-800-53-rev5", force_refresh=True)

        # List cached documents
        for entry in cache.list_entries():
            print(f"{entry.name}: {entry.cached_at}")
    """

    INDEX_FILE = "cache_index.json"

    def __init__(
        self,
        cache_dir: Path | str | None = None,
        cache_ttl_days: int = DEFAULT_CACHE_TTL_DAYS,
        offline_mode: bool = False,
    ) -> None:
        """
        Initialize the OSCAL cache.

        Args:
            cache_dir: Directory for cached files (default: ~/.attestful/oscal_cache)
            cache_ttl_days: Days before cache entries expire
            offline_mode: If True, never attempt network downloads
        """
        self.cache_dir = Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR
        self.cache_ttl_days = cache_ttl_days
        self.offline_mode = offline_mode

        self._entries: dict[str, CacheEntry] = {}
        self._loaded = False

        # Ensure cache directory exists
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _load_index(self) -> None:
        """Load the cache index from disk."""
        if self._loaded:
            return

        index_path = self.cache_dir / self.INDEX_FILE
        if index_path.exists():
            try:
                with open(index_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._entries = {
                        k: CacheEntry.from_dict(v) for k, v in data.get("entries", {}).items()
                    }
                logger.debug(f"Loaded cache index with {len(self._entries)} entries")
            except Exception as e:
                logger.warning(f"Failed to load cache index: {e}")
                self._entries = {}

        self._loaded = True

    def _save_index(self) -> None:
        """Save the cache index to disk."""
        index_path = self.cache_dir / self.INDEX_FILE
        data = {
            "version": "1.0",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "entries": {k: v.to_dict() for k, v in self._entries.items()},
        }
        with open(index_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _compute_hash(self, content: bytes) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(content).hexdigest()

    def _generate_cache_id(self, identifier: str) -> str:
        """Generate a safe cache ID from an identifier."""
        # Normalize the identifier
        safe_id = identifier.lower().replace(" ", "-").replace("/", "_")
        return safe_id

    def get_catalog(
        self,
        identifier: str,
        *,
        force_refresh: bool = False,
    ) -> Path:
        """
        Get a catalog from cache, downloading if needed.

        Args:
            identifier: Catalog identifier (e.g., "nist-800-53-rev5") or URL
            force_refresh: Force re-download even if cached

        Returns:
            Path to the cached catalog file

        Raises:
            CatalogError: If catalog cannot be retrieved
        """
        self._load_index()

        cache_id = self._generate_cache_id(identifier)

        # Check if we have it cached and it's valid
        if not force_refresh and cache_id in self._entries:
            entry = self._entries[cache_id]
            if not entry.is_expired:
                cache_path = Path(entry.file_path)
                if cache_path.exists():
                    logger.debug(f"Using cached catalog: {identifier}")
                    return cache_path

        # Check if it's a known catalog
        if identifier in OFFICIAL_CATALOGS:
            catalog_info = OFFICIAL_CATALOGS[identifier]
            return self._download_and_cache(
                url=catalog_info["url"],
                cache_id=cache_id,
                name=catalog_info["name"],
                version=catalog_info.get("version", ""),
                document_type=catalog_info.get("type", "catalog"),
            )

        # Check if it's a URL
        if identifier.startswith("http://") or identifier.startswith("https://"):
            return self._download_and_cache(
                url=identifier,
                cache_id=cache_id,
                name=identifier,
            )

        # Check if it's a local file path
        local_path = Path(identifier)
        if local_path.exists():
            return self._cache_local_file(local_path, cache_id)

        # Check bundled catalogs
        bundled_path = self._get_bundled_catalog(identifier)
        if bundled_path and bundled_path.exists():
            return self._cache_local_file(bundled_path, cache_id, is_bundled=True)

        raise CatalogError(
            f"Catalog not found: {identifier}. "
            f"Available: {', '.join(OFFICIAL_CATALOGS.keys())}",
            catalog_id=identifier,
        )

    def _download_and_cache(
        self,
        url: str,
        cache_id: str,
        name: str = "",
        version: str = "",
        document_type: str = "catalog",
    ) -> Path:
        """Download a document and add to cache."""
        if self.offline_mode:
            raise CatalogError(
                f"Cannot download in offline mode: {url}",
                catalog_id=cache_id,
            )

        logger.info(f"Downloading OSCAL document: {url}")

        try:
            response = requests.get(url, timeout=60)
            response.raise_for_status()
            content = response.content
        except requests.RequestException as e:
            raise CatalogError(
                f"Failed to download: {e}",
                catalog_id=cache_id,
                cause=e,
            ) from e

        # Determine file extension from URL or content type
        parsed_url = urlparse(url)
        ext = Path(parsed_url.path).suffix or ".json"

        # Save to cache
        cache_file = self.cache_dir / f"{cache_id}{ext}"
        with open(cache_file, "wb") as f:
            f.write(content)

        # Create cache entry
        entry = CacheEntry(
            cache_id=cache_id,
            source_url=url,
            name=name or cache_id,
            version=version,
            document_type=document_type,
            content_hash=self._compute_hash(content),
            file_path=str(cache_file),
            cached_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=self.cache_ttl_days),
            size_bytes=len(content),
        )

        self._entries[cache_id] = entry
        self._save_index()

        logger.info(f"Cached {document_type}: {name} ({len(content)} bytes)")
        return cache_file

    def _cache_local_file(
        self,
        source_path: Path,
        cache_id: str,
        is_bundled: bool = False,
    ) -> Path:
        """Copy a local file to the cache."""
        content = source_path.read_bytes()

        # Determine file extension
        ext = source_path.suffix or ".json"

        # Copy to cache
        cache_file = self.cache_dir / f"{cache_id}{ext}"
        shutil.copy2(source_path, cache_file)

        # Create cache entry
        entry = CacheEntry(
            cache_id=cache_id,
            source_path=str(source_path),
            name=source_path.stem,
            document_type="catalog",
            content_hash=self._compute_hash(content),
            file_path=str(cache_file),
            cached_at=datetime.now(timezone.utc),
            expires_at=None if is_bundled else datetime.now(timezone.utc) + timedelta(days=self.cache_ttl_days),
            size_bytes=len(content),
            is_bundled=is_bundled,
        )

        self._entries[cache_id] = entry
        self._save_index()

        logger.info(f"Cached local file: {source_path.name}")
        return cache_file

    def _get_bundled_catalog(self, identifier: str) -> Path | None:
        """Check for bundled catalogs shipped with Attestful."""
        # Check in package data directory
        import importlib.resources

        try:
            # Try to find bundled catalogs
            with importlib.resources.files("attestful.data.oscal.catalogs") as data_path:
                bundled_path = Path(data_path) / f"{identifier}.json"
                if bundled_path.exists():
                    return bundled_path
        except Exception:
            pass

        # Check relative to package
        package_dir = Path(__file__).parent.parent
        data_dir = package_dir / "data" / "oscal" / "catalogs"
        if data_dir.exists():
            for ext in (".json", ".yaml", ".xml"):
                bundled_path = data_dir / f"{identifier}{ext}"
                if bundled_path.exists():
                    return bundled_path

        return None

    def get_profile(
        self,
        identifier: str,
        *,
        force_refresh: bool = False,
    ) -> Path:
        """
        Get a profile from cache, downloading if needed.

        Similar to get_catalog but for OSCAL profiles.
        """
        return self.get_catalog(identifier, force_refresh=force_refresh)

    def add_from_file(
        self,
        file_path: Path | str,
        cache_id: str | None = None,
        name: str = "",
        document_type: str = "catalog",
    ) -> CacheEntry:
        """
        Manually add a file to the cache.

        Useful for air-gapped deployments where catalogs are transferred manually.

        Args:
            file_path: Path to the OSCAL document
            cache_id: Optional cache identifier (auto-generated if not provided)
            name: Display name for the document
            document_type: Type of document (catalog, profile, etc.)

        Returns:
            CacheEntry for the added document
        """
        self._load_index()

        file_path = Path(file_path)
        if not file_path.exists():
            raise CatalogError(f"File not found: {file_path}")

        if not cache_id:
            cache_id = self._generate_cache_id(file_path.stem)

        content = file_path.read_bytes()
        ext = file_path.suffix or ".json"

        # Copy to cache
        cache_file = self.cache_dir / f"{cache_id}{ext}"
        shutil.copy2(file_path, cache_file)

        entry = CacheEntry(
            cache_id=cache_id,
            source_path=str(file_path),
            name=name or file_path.stem,
            document_type=document_type,
            content_hash=self._compute_hash(content),
            file_path=str(cache_file),
            size_bytes=len(content),
        )

        self._entries[cache_id] = entry
        self._save_index()

        logger.info(f"Added to cache: {name or file_path.name}")
        return entry

    def remove(self, cache_id: str) -> bool:
        """
        Remove an entry from the cache.

        Args:
            cache_id: The cache identifier to remove

        Returns:
            True if removed, False if not found
        """
        self._load_index()

        if cache_id not in self._entries:
            return False

        entry = self._entries[cache_id]

        # Delete the file
        cache_file = Path(entry.file_path)
        if cache_file.exists():
            cache_file.unlink()

        del self._entries[cache_id]
        self._save_index()

        logger.info(f"Removed from cache: {cache_id}")
        return True

    def clear(self) -> int:
        """
        Clear all cached entries.

        Returns:
            Number of entries removed
        """
        self._load_index()

        count = len(self._entries)

        for entry in self._entries.values():
            cache_file = Path(entry.file_path)
            if cache_file.exists():
                cache_file.unlink()

        self._entries.clear()
        self._save_index()

        logger.info(f"Cleared cache: {count} entries removed")
        return count

    def list_entries(self) -> list[CacheEntry]:
        """List all cache entries."""
        self._load_index()
        return list(self._entries.values())

    def get_entry(self, cache_id: str) -> CacheEntry | None:
        """Get a specific cache entry."""
        self._load_index()
        return self._entries.get(cache_id)

    def list_available_catalogs(self) -> dict[str, dict[str, Any]]:
        """
        List all available catalogs (both cached and downloadable).

        Returns:
            Dictionary mapping catalog IDs to their info
        """
        self._load_index()

        result: dict[str, dict[str, Any]] = {}

        # Add official catalogs
        for catalog_id, info in OFFICIAL_CATALOGS.items():
            cached_entry = self._entries.get(catalog_id)
            result[catalog_id] = {
                "name": info["name"],
                "version": info.get("version", ""),
                "url": info["url"],
                "type": info.get("type", "catalog"),
                "cached": cached_entry is not None,
                "cached_at": cached_entry.cached_at.isoformat() if cached_entry else None,
                "expired": cached_entry.is_expired if cached_entry else None,
            }

        # Add custom cached entries
        for cache_id, entry in self._entries.items():
            if cache_id not in result:
                result[cache_id] = {
                    "name": entry.name,
                    "version": entry.version,
                    "url": entry.source_url,
                    "path": entry.source_path,
                    "type": entry.document_type,
                    "cached": True,
                    "cached_at": entry.cached_at.isoformat(),
                    "expired": entry.is_expired,
                    "is_bundled": entry.is_bundled,
                }

        return result

    def refresh_expired(self) -> list[str]:
        """
        Refresh all expired cache entries.

        Returns:
            List of cache IDs that were refreshed
        """
        self._load_index()

        refreshed: list[str] = []

        for cache_id, entry in list(self._entries.items()):
            if entry.is_expired and entry.source_url:
                try:
                    self.get_catalog(cache_id, force_refresh=True)
                    refreshed.append(cache_id)
                except CatalogError as e:
                    logger.warning(f"Failed to refresh {cache_id}: {e}")

        return refreshed

    def get_cache_statistics(self) -> dict[str, Any]:
        """Get cache statistics."""
        self._load_index()

        total_size = sum(e.size_bytes for e in self._entries.values())
        expired_count = sum(1 for e in self._entries.values() if e.is_expired)
        bundled_count = sum(1 for e in self._entries.values() if e.is_bundled)

        by_type: dict[str, int] = {}
        for entry in self._entries.values():
            by_type[entry.document_type] = by_type.get(entry.document_type, 0) + 1

        return {
            "cache_dir": str(self.cache_dir),
            "total_entries": len(self._entries),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "expired_count": expired_count,
            "bundled_count": bundled_count,
            "by_type": by_type,
            "offline_mode": self.offline_mode,
            "cache_ttl_days": self.cache_ttl_days,
        }


# =============================================================================
# Convenience Functions
# =============================================================================


# Global cache instance
_global_cache: OSCALCache | None = None


def get_oscal_cache(
    cache_dir: Path | str | None = None,
    offline_mode: bool = False,
) -> OSCALCache:
    """
    Get the global OSCAL cache instance.

    Args:
        cache_dir: Optional custom cache directory
        offline_mode: If True, disable network downloads

    Returns:
        OSCALCache instance
    """
    global _global_cache

    if _global_cache is None or cache_dir is not None:
        _global_cache = OSCALCache(
            cache_dir=cache_dir,
            offline_mode=offline_mode,
        )

    return _global_cache


def download_all_official_catalogs(
    cache_dir: Path | str | None = None,
) -> list[str]:
    """
    Download all official OSCAL catalogs.

    Useful for pre-populating the cache for offline use.

    Args:
        cache_dir: Optional custom cache directory

    Returns:
        List of downloaded catalog IDs
    """
    cache = OSCALCache(cache_dir=cache_dir)
    downloaded: list[str] = []

    for catalog_id in OFFICIAL_CATALOGS:
        if OFFICIAL_CATALOGS[catalog_id].get("type") != "profile":
            try:
                cache.get_catalog(catalog_id, force_refresh=True)
                downloaded.append(catalog_id)
            except CatalogError as e:
                logger.error(f"Failed to download {catalog_id}: {e}")

    return downloaded


def download_all_official_profiles(
    cache_dir: Path | str | None = None,
) -> list[str]:
    """
    Download all official OSCAL profiles (FedRAMP baselines).

    Useful for pre-populating the cache for offline use.

    Args:
        cache_dir: Optional custom cache directory

    Returns:
        List of downloaded profile IDs
    """
    cache = OSCALCache(cache_dir=cache_dir)
    downloaded: list[str] = []

    for profile_id, info in OFFICIAL_PROFILES.items():
        try:
            cache.get_catalog(profile_id, force_refresh=True)
            downloaded.append(profile_id)
        except CatalogError as e:
            logger.error(f"Failed to download {profile_id}: {e}")

    return downloaded


def export_cache_for_offline(
    output_dir: Path | str,
    cache_dir: Path | str | None = None,
) -> Path:
    """
    Export the OSCAL cache for offline deployment.

    Creates a portable copy that can be transferred to air-gapped systems.

    Args:
        output_dir: Directory for the export
        cache_dir: Source cache directory

    Returns:
        Path to the export directory
    """
    cache = OSCALCache(cache_dir=cache_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Copy all cached files
    for entry in cache.list_entries():
        source = Path(entry.file_path)
        if source.exists():
            dest = output_dir / source.name
            shutil.copy2(source, dest)

    # Copy the index
    index_source = cache.cache_dir / cache.INDEX_FILE
    if index_source.exists():
        shutil.copy2(index_source, output_dir / cache.INDEX_FILE)

    logger.info(f"Exported cache to {output_dir}")
    return output_dir


def import_cache_from_offline(
    source_dir: Path | str,
    cache_dir: Path | str | None = None,
) -> int:
    """
    Import OSCAL cache from an offline export.

    Args:
        source_dir: Directory containing the export
        cache_dir: Target cache directory

    Returns:
        Number of documents imported
    """
    cache = OSCALCache(cache_dir=cache_dir)
    source_dir = Path(source_dir)

    if not source_dir.exists():
        raise CatalogError(f"Source directory not found: {source_dir}")

    count = 0

    # Copy all files
    for file_path in source_dir.glob("*.json"):
        if file_path.name != cache.INDEX_FILE:
            cache.add_from_file(file_path)
            count += 1

    for file_path in source_dir.glob("*.yaml"):
        cache.add_from_file(file_path)
        count += 1

    logger.info(f"Imported {count} documents from {source_dir}")
    return count
