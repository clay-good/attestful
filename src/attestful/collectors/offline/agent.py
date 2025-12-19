"""
Air-Gapped Collection Agent.

Standalone agent for collecting evidence in isolated/air-gapped networks.

Features:
- Runs as a standalone process on isolated networks
- Collects evidence using locally stored credentials
- Generates signed evidence bundles for transfer
- Supports sneakernet transfer via USB
- Scheduled collection with configurable intervals
- Local caching for incremental exports
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event, Thread
from typing import Any, Callable

from attestful.collectors.base import BaseCollector, collector_registry
from attestful.collectors.offline.bundle import BundleFormat
from attestful.collectors.offline.exporter import BundleExporter, ExportConfig, ExportResult
from attestful.core.exceptions import ConfigurationError
from attestful.core.logging import get_logger
from attestful.core.models import CollectionResult, Evidence

logger = get_logger(__name__)


@dataclass
class AgentConfig:
    """Configuration for offline collection agent."""

    # Agent identity
    agent_id: str = ""
    agent_name: str = "Attestful Offline Agent"
    organization_id: str = ""
    organization_name: str = ""

    # Collection settings
    collectors: list[str] = field(default_factory=list)  # Collector names to use
    collection_interval_hours: float = 24.0  # How often to collect
    run_on_startup: bool = True  # Collect immediately on start

    # Storage settings
    data_dir: Path = field(default_factory=lambda: Path.home() / ".attestful" / "offline")
    evidence_cache_days: int = 90  # How long to keep cached evidence
    max_cache_size_mb: int = 5000  # Maximum cache size

    # Export settings
    export_dir: Path = field(default_factory=lambda: Path.home() / ".attestful" / "exports")
    bundle_format: BundleFormat = BundleFormat.TAR_GZ
    auto_export: bool = True  # Automatically export after collection
    incremental_export: bool = True  # Only export new evidence

    # Signing settings
    sign_bundles: bool = True
    signing_key_path: Path | None = None

    # Credentials (stored locally for air-gapped operation)
    credentials_file: Path | None = None

    # Logging
    log_file: Path | None = None
    log_level: str = "INFO"

    # Daemon settings
    daemon_mode: bool = False
    pid_file: Path | None = None


@dataclass
class AgentState:
    """Runtime state of the offline agent."""

    is_running: bool = False
    last_collection_time: datetime | None = None
    last_export_time: datetime | None = None
    next_collection_time: datetime | None = None
    total_collections: int = 0
    total_exports: int = 0
    evidence_cached: int = 0
    cache_size_bytes: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_running": self.is_running,
            "last_collection_time": (
                self.last_collection_time.isoformat()
                if self.last_collection_time
                else None
            ),
            "last_export_time": (
                self.last_export_time.isoformat() if self.last_export_time else None
            ),
            "next_collection_time": (
                self.next_collection_time.isoformat()
                if self.next_collection_time
                else None
            ),
            "total_collections": self.total_collections,
            "total_exports": self.total_exports,
            "evidence_cached": self.evidence_cached,
            "cache_size_bytes": self.cache_size_bytes,
            "errors": self.errors[-10:],  # Last 10 errors
        }


class OfflineAgent:
    """
    Standalone agent for air-gapped evidence collection.

    Runs as a long-running process on isolated networks, collecting
    evidence on a schedule and generating signed bundles for transfer.

    Example:
        agent = OfflineAgent(
            config=AgentConfig(
                collectors=["okta", "jamf", "google_workspace"],
                collection_interval_hours=24,
                export_dir=Path("/mnt/usb/exports"),
                sign_bundles=True,
            )
        )

        # Run once
        agent.collect_and_export()

        # Or run as daemon
        agent.run()
    """

    def __init__(self, config: AgentConfig | None = None) -> None:
        """
        Initialize offline agent.

        Args:
            config: Agent configuration
        """
        self.config = config or AgentConfig()
        self.state = AgentState()
        self._stop_event = Event()
        self._collection_thread: Thread | None = None
        self._collectors: dict[str, BaseCollector] = {}
        self._credentials: dict[str, dict[str, Any]] = {}

        # Ensure directories exist
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        self.config.export_dir.mkdir(parents=True, exist_ok=True)

        # Generate agent ID if not set
        if not self.config.agent_id:
            import socket
            from uuid import uuid4

            hostname = socket.gethostname()
            self.config.agent_id = f"{hostname}-{str(uuid4())[:8]}"

    def initialize(self) -> None:
        """
        Initialize the agent.

        Loads credentials and initializes collectors.
        """
        logger.info(f"Initializing offline agent: {self.config.agent_id}")

        # Load credentials
        if self.config.credentials_file and self.config.credentials_file.exists():
            self._load_credentials()

        # Initialize collectors
        for collector_name in self.config.collectors:
            try:
                self._initialize_collector(collector_name)
            except Exception as e:
                error_msg = f"Failed to initialize collector {collector_name}: {e}"
                logger.error(error_msg)
                self.state.errors.append(error_msg)

        # Load cached state
        self._load_state()

        logger.info(
            f"Agent initialized with {len(self._collectors)} collectors: "
            f"{', '.join(self._collectors.keys())}"
        )

    def _load_credentials(self) -> None:
        """Load credentials from local file."""
        if not self.config.credentials_file:
            return

        try:
            with open(self.config.credentials_file, "r") as f:
                self._credentials = json.load(f)
            logger.info("Loaded credentials from file")
        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")

    def _initialize_collector(self, collector_name: str) -> None:
        """Initialize a single collector."""
        collector_class = collector_registry.get(collector_name)
        if not collector_class:
            raise ConfigurationError(f"Unknown collector: {collector_name}")

        # Get credentials for this collector
        creds = self._credentials.get(collector_name, {})

        # Create collector instance
        collector = collector_class(**creds)
        self._collectors[collector_name] = collector

    def _load_state(self) -> None:
        """Load agent state from disk."""
        state_file = self.config.data_dir / "agent_state.json"
        if state_file.exists():
            try:
                with open(state_file, "r") as f:
                    data = json.load(f)

                if data.get("last_collection_time"):
                    self.state.last_collection_time = datetime.fromisoformat(
                        data["last_collection_time"]
                    )
                if data.get("last_export_time"):
                    self.state.last_export_time = datetime.fromisoformat(
                        data["last_export_time"]
                    )
                self.state.total_collections = data.get("total_collections", 0)
                self.state.total_exports = data.get("total_exports", 0)

            except Exception as e:
                logger.warning(f"Failed to load state: {e}")

    def _save_state(self) -> None:
        """Save agent state to disk."""
        state_file = self.config.data_dir / "agent_state.json"
        try:
            with open(state_file, "w") as f:
                json.dump(self.state.to_dict(), f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save state: {e}")

    def collect(self) -> list[CollectionResult]:
        """
        Run evidence collection from all configured collectors.

        Returns:
            List of CollectionResult from each collector
        """
        logger.info("Starting evidence collection")
        results: list[CollectionResult] = []

        for name, collector in self._collectors.items():
            logger.info(f"Collecting from {name}")

            try:
                # Validate credentials
                if not collector.validate_credentials():
                    error_msg = f"Credential validation failed for {name}"
                    logger.error(error_msg)
                    self.state.errors.append(error_msg)
                    continue

                # Collect evidence
                result = collector.collect_evidence()
                results.append(result)

                logger.info(
                    f"Collected {len(result.evidence_items)} evidence items from {name}"
                )

                # Cache evidence locally
                self._cache_evidence(name, result)

            except Exception as e:
                error_msg = f"Collection failed for {name}: {e}"
                logger.error(error_msg)
                self.state.errors.append(error_msg)

        # Update state
        self.state.last_collection_time = datetime.now(timezone.utc)
        self.state.total_collections += 1
        self._update_cache_stats()
        self._save_state()

        total_evidence = sum(len(r.evidence_items) for r in results)
        logger.info(f"Collection complete: {total_evidence} total evidence items")

        return results

    def _cache_evidence(self, collector_name: str, result: CollectionResult) -> None:
        """Cache collected evidence locally."""
        cache_dir = self.config.data_dir / "cache" / collector_name
        cache_dir.mkdir(parents=True, exist_ok=True)

        for evidence in result.evidence_items:
            date_str = evidence.collected_at.strftime("%Y-%m-%d")
            file_path = cache_dir / date_str / f"{evidence.id}.json"
            file_path.parent.mkdir(parents=True, exist_ok=True)

            with open(file_path, "w") as f:
                json.dump(evidence.to_dict(), f, indent=2, default=str)

    def _update_cache_stats(self) -> None:
        """Update cache statistics."""
        cache_dir = self.config.data_dir / "cache"
        if not cache_dir.exists():
            return

        total_files = 0
        total_size = 0

        for file_path in cache_dir.rglob("*.json"):
            total_files += 1
            total_size += file_path.stat().st_size

        self.state.evidence_cached = total_files
        self.state.cache_size_bytes = total_size

    def export(
        self,
        results: list[CollectionResult] | None = None,
        incremental: bool | None = None,
    ) -> ExportResult:
        """
        Export evidence to a bundle.

        Args:
            results: Collection results to export (or use cached)
            incremental: Only export since last export

        Returns:
            ExportResult with bundle details
        """
        logger.info("Starting evidence export")

        # Use cached evidence if no results provided
        if results is None:
            results = self._load_cached_evidence(incremental)

        export_config = ExportConfig(
            output_dir=self.config.export_dir,
            bundle_format=self.config.bundle_format,
            organization_id=self.config.organization_id,
            organization_name=self.config.organization_name,
            description=f"Export from {self.config.agent_name} ({self.config.agent_id})",
            sign_bundle=self.config.sign_bundles,
            signing_key_path=self.config.signing_key_path,
        )

        exporter = BundleExporter(export_config)
        result = exporter.export_collection_results(results)

        if result.success:
            self.state.last_export_time = datetime.now(timezone.utc)
            self.state.total_exports += 1
            self._save_state()

            logger.info(
                f"Export complete: {result.total_files} files, "
                f"bundle: {result.bundle_path}"
            )
        else:
            error_msg = f"Export failed: {result.errors}"
            logger.error(error_msg)
            self.state.errors.append(error_msg)

        return result

    def _load_cached_evidence(
        self,
        incremental: bool | None = None,
    ) -> list[CollectionResult]:
        """Load evidence from local cache."""
        if incremental is None:
            incremental = self.config.incremental_export

        cache_dir = self.config.data_dir / "cache"
        if not cache_dir.exists():
            return []

        since: datetime | None = None
        if incremental and self.state.last_export_time:
            since = self.state.last_export_time

        results_by_platform: dict[str, CollectionResult] = {}

        for platform_dir in cache_dir.iterdir():
            if not platform_dir.is_dir():
                continue

            platform = platform_dir.name
            evidence_items: list[Evidence] = []

            for file_path in platform_dir.rglob("*.json"):
                try:
                    with open(file_path, "r") as f:
                        data = json.load(f)

                    collected_at = data.get("collected_at")
                    if isinstance(collected_at, str):
                        collected_at = datetime.fromisoformat(
                            collected_at.replace("Z", "+00:00")
                        )
                    else:
                        collected_at = datetime.now(timezone.utc)

                    # Filter by time if incremental
                    if since and collected_at <= since:
                        continue

                    evidence = Evidence(
                        id=data.get("id", ""),
                        platform=data.get("platform", platform),
                        evidence_type=data.get("evidence_type", ""),
                        collected_at=collected_at,
                        raw_data=data.get("raw_data", {}),
                        metadata=data.get("metadata", {}),
                        source_id=data.get("source_id"),
                    )
                    evidence_items.append(evidence)

                except Exception as e:
                    logger.warning(f"Failed to load cached evidence {file_path}: {e}")

            if evidence_items:
                result = CollectionResult(
                    success=True,
                    platform=platform,
                    evidence_items=evidence_items,
                )
                results_by_platform[platform] = result

        return list(results_by_platform.values())

    def collect_and_export(self) -> tuple[list[CollectionResult], ExportResult]:
        """
        Run collection and export in one operation.

        Returns:
            Tuple of (collection results, export result)
        """
        results = self.collect()

        if not any(r.evidence_items for r in results):
            logger.info("No evidence collected, skipping export")
            return results, ExportResult(success=True, warnings=["No evidence to export"])

        if self.config.auto_export:
            export_result = self.export(results)
            return results, export_result

        return results, ExportResult(success=True, warnings=["Auto-export disabled"])

    def run(self) -> None:
        """
        Run the agent in daemon mode.

        Collects evidence on schedule and exports bundles.
        """
        self.initialize()
        self.state.is_running = True

        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)

        # Write PID file if configured
        if self.config.pid_file:
            with open(self.config.pid_file, "w") as f:
                f.write(str(os.getpid()))

        logger.info(f"Agent {self.config.agent_id} starting in daemon mode")

        try:
            # Initial collection if configured
            if self.config.run_on_startup:
                self.collect_and_export()

            # Main loop
            while not self._stop_event.is_set():
                # Calculate next collection time
                interval = timedelta(hours=self.config.collection_interval_hours)
                if self.state.last_collection_time:
                    self.state.next_collection_time = (
                        self.state.last_collection_time + interval
                    )
                else:
                    self.state.next_collection_time = datetime.now(timezone.utc)

                # Wait until next collection
                now = datetime.now(timezone.utc)
                if self.state.next_collection_time > now:
                    wait_seconds = (self.state.next_collection_time - now).total_seconds()
                    logger.info(f"Next collection in {wait_seconds / 3600:.1f} hours")
                    self._stop_event.wait(timeout=min(wait_seconds, 3600))

                if self._stop_event.is_set():
                    break

                # Run collection
                if datetime.now(timezone.utc) >= self.state.next_collection_time:
                    try:
                        self.collect_and_export()
                    except Exception as e:
                        error_msg = f"Collection cycle failed: {e}"
                        logger.error(error_msg)
                        self.state.errors.append(error_msg)

                # Clean up old cache entries
                self._cleanup_cache()

        finally:
            self.state.is_running = False
            self._save_state()

            # Remove PID file
            if self.config.pid_file and self.config.pid_file.exists():
                self.config.pid_file.unlink()

            logger.info("Agent stopped")

    def _handle_shutdown(self, signum: int, frame: Any) -> None:
        """Handle shutdown signal."""
        logger.info(f"Received signal {signum}, shutting down")
        self._stop_event.set()

    def _cleanup_cache(self) -> None:
        """Clean up old cached evidence."""
        cache_dir = self.config.data_dir / "cache"
        if not cache_dir.exists():
            return

        cutoff = datetime.now(timezone.utc) - timedelta(days=self.config.evidence_cache_days)

        for platform_dir in cache_dir.iterdir():
            if not platform_dir.is_dir():
                continue

            for date_dir in platform_dir.iterdir():
                if not date_dir.is_dir():
                    continue

                try:
                    dir_date = datetime.strptime(date_dir.name, "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    )
                    if dir_date < cutoff:
                        import shutil

                        shutil.rmtree(date_dir)
                        logger.debug(f"Cleaned up old cache: {date_dir}")
                except ValueError:
                    pass  # Invalid date directory name

    def stop(self) -> None:
        """Stop the agent."""
        self._stop_event.set()

    def get_status(self) -> dict[str, Any]:
        """Get agent status."""
        return {
            "agent_id": self.config.agent_id,
            "agent_name": self.config.agent_name,
            "state": self.state.to_dict(),
            "collectors": list(self._collectors.keys()),
            "config": {
                "collection_interval_hours": self.config.collection_interval_hours,
                "auto_export": self.config.auto_export,
                "sign_bundles": self.config.sign_bundles,
            },
        }


# =============================================================================
# Convenience Functions
# =============================================================================


def run_offline_collection(
    collectors: list[str],
    *,
    output_dir: Path | str = ".",
    organization_name: str = "",
    sign_bundle: bool = True,
    signing_key_path: Path | str | None = None,
) -> tuple[list[CollectionResult], ExportResult]:
    """
    Run a one-time offline collection and export.

    Convenience function for simple collection scenarios.

    Args:
        collectors: List of collector names to use
        output_dir: Directory for bundle output
        organization_name: Organization name for metadata
        sign_bundle: Whether to sign the bundle
        signing_key_path: Path to signing key

    Returns:
        Tuple of (collection results, export result)

    Example:
        results, export = run_offline_collection(
            collectors=["okta", "jamf"],
            output_dir="/mnt/usb/exports",
            organization_name="Acme Corp",
        )
        print(f"Bundle: {export.bundle_path}")
    """
    config = AgentConfig(
        collectors=collectors,
        export_dir=Path(output_dir),
        organization_name=organization_name,
        sign_bundles=sign_bundle,
        signing_key_path=Path(signing_key_path) if signing_key_path else None,
        auto_export=True,
    )

    agent = OfflineAgent(config)
    agent.initialize()

    return agent.collect_and_export()


def create_agent_config_file(
    output_path: Path | str,
    collectors: list[str] | None = None,
    **kwargs: Any,
) -> Path:
    """
    Create a sample agent configuration file.

    Args:
        output_path: Path for config file
        collectors: List of collectors to configure
        **kwargs: Additional config options

    Returns:
        Path to created config file
    """
    output_path = Path(output_path)

    config = {
        "agent_name": kwargs.get("agent_name", "Attestful Offline Agent"),
        "organization_id": kwargs.get("organization_id", ""),
        "organization_name": kwargs.get("organization_name", ""),
        "collectors": collectors or [],
        "collection_interval_hours": kwargs.get("collection_interval_hours", 24),
        "run_on_startup": kwargs.get("run_on_startup", True),
        "auto_export": kwargs.get("auto_export", True),
        "sign_bundles": kwargs.get("sign_bundles", True),
        "bundle_format": kwargs.get("bundle_format", "tar.gz"),
        "evidence_cache_days": kwargs.get("evidence_cache_days", 90),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(config, f, indent=2)

    return output_path
