"""
Unified collector base class.

Supports dual-mode operation:
- Resource mode: Collect infrastructure resources for compliance checking
- Evidence mode: Collect evidence artifacts for proof gathering
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, TypeVar

from attestful.core.exceptions import (
    AuthenticationError,
    CollectionError,
    RateLimitError,
)
from attestful.core.logging import get_logger
from attestful.core.models import CollectionResult, Evidence, Resource

logger = get_logger("collectors")

T = TypeVar("T")


class CollectorMode(str, Enum):
    """Mode of collection."""

    RESOURCE = "resource"  # Collect resources for compliance checking
    EVIDENCE = "evidence"  # Collect evidence for proof gathering
    BOTH = "both"  # Collector supports both modes


@dataclass
class CollectorMetadata:
    """Metadata about a collector."""

    name: str
    platform: str
    description: str
    mode: CollectorMode
    resource_types: list[str] = field(default_factory=list)
    evidence_types: list[str] = field(default_factory=list)
    requires_credentials: bool = True
    version: str = "1.0.0"


class BaseCollector(ABC):
    """
    Abstract base class for all collectors.

    Collectors can operate in two modes:
    - Resource mode: Collects infrastructure resources (EC2, S3, IAM, etc.)
      for evaluating against compliance checks
    - Evidence mode: Collects evidence artifacts (MFA status, audit logs, etc.)
      for proving control implementation

    Subclasses should implement either or both of:
    - collect_resources() for resource collection
    - collect_evidence() for evidence collection
    """

    # Class-level metadata (override in subclasses)
    metadata: CollectorMetadata = CollectorMetadata(
        name="BaseCollector",
        platform="unknown",
        description="Base collector class",
        mode=CollectorMode.BOTH,
    )

    def __init__(
        self,
        *,
        rate_limit_per_second: float = 10.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        timeout: float = 30.0,
    ) -> None:
        """
        Initialize the collector.

        Args:
            rate_limit_per_second: Maximum requests per second
            max_retries: Maximum retry attempts for failed requests
            retry_delay: Base delay between retries (exponential backoff)
            timeout: Request timeout in seconds
        """
        self.rate_limit_per_second = rate_limit_per_second
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout = timeout

        self._last_request_time: float = 0.0
        self._request_count: int = 0

        self.logger = get_logger(
            f"collectors.{self.metadata.platform}",
            platform=self.metadata.platform,
        )

    # =========================================================================
    # Abstract Methods
    # =========================================================================

    @abstractmethod
    def validate_credentials(self) -> bool:
        """
        Validate that credentials are configured and working.

        Returns:
            True if credentials are valid, False otherwise

        Raises:
            AuthenticationError: If authentication fails
        """
        ...

    def collect_resources(
        self,
        *,
        resource_types: list[str] | None = None,
        regions: list[str] | None = None,
        filters: dict[str, Any] | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[Resource]:
        """
        Collect infrastructure resources for compliance checking.

        Override this method in subclasses that support resource collection.

        Args:
            resource_types: Specific resource types to collect (None = all)
            regions: Specific regions to collect from (None = all)
            filters: Additional filters to apply
            progress_callback: Optional callback(current, total) for progress

        Returns:
            List of collected Resource objects

        Raises:
            CollectionError: If collection fails
            NotImplementedError: If resource collection not supported
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not support resource collection"
        )

    def collect_evidence(
        self,
        *,
        evidence_types: list[str] | None = None,
        since: datetime | None = None,
        filters: dict[str, Any] | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> CollectionResult:
        """
        Collect evidence artifacts for proof gathering.

        Override this method in subclasses that support evidence collection.

        Args:
            evidence_types: Specific evidence types to collect (None = all)
            since: Only collect evidence modified after this time
            filters: Additional filters to apply
            progress_callback: Optional callback(current, total) for progress

        Returns:
            CollectionResult with collected evidence

        Raises:
            CollectionError: If collection fails
            NotImplementedError: If evidence collection not supported
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not support evidence collection"
        )

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def _rate_limit(self) -> None:
        """
        Apply rate limiting between requests.

        Blocks until enough time has passed since the last request.
        """
        if self.rate_limit_per_second <= 0:
            return

        min_interval = 1.0 / self.rate_limit_per_second
        elapsed = time.monotonic() - self._last_request_time

        if elapsed < min_interval:
            sleep_time = min_interval - elapsed
            time.sleep(sleep_time)

        self._last_request_time = time.monotonic()
        self._request_count += 1

    def _with_retry(
        self,
        operation: Callable[[], T],
        operation_name: str = "operation",
    ) -> T:
        """
        Execute an operation with retry logic.

        Args:
            operation: The operation to execute
            operation_name: Name for logging

        Returns:
            Result of the operation

        Raises:
            CollectionError: If all retries fail
        """
        last_error: Exception | None = None

        for attempt in range(self.max_retries):
            try:
                self._rate_limit()
                return operation()

            except RateLimitError as e:
                # Use retry-after if provided
                delay = e.retry_after or (self.retry_delay * (2**attempt))
                self.logger.warning(
                    f"Rate limited on {operation_name}, "
                    f"waiting {delay}s (attempt {attempt + 1}/{self.max_retries})"
                )
                time.sleep(delay)
                last_error = e

            except AuthenticationError:
                # Don't retry auth errors
                raise

            except Exception as e:
                delay = self.retry_delay * (2**attempt)
                self.logger.warning(
                    f"Error in {operation_name}: {e}, "
                    f"retrying in {delay}s (attempt {attempt + 1}/{self.max_retries})"
                )
                time.sleep(delay)
                last_error = e

        raise CollectionError(
            f"Failed after {self.max_retries} attempts: {last_error}",
            platform=self.metadata.platform,
            cause=last_error,
        )

    def _create_evidence(
        self,
        evidence_type: str,
        raw_data: dict[str, Any],
        *,
        source_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Evidence:
        """
        Create an Evidence object with common fields populated.

        Args:
            evidence_type: Type of evidence
            raw_data: The raw evidence data
            source_id: Platform-specific identifier
            metadata: Additional metadata

        Returns:
            Evidence object
        """
        return Evidence(
            platform=self.metadata.platform,
            evidence_type=evidence_type,
            raw_data=raw_data,
            source_id=source_id,
            metadata=metadata or {},
            collected_at=datetime.now(timezone.utc),
        )

    def _create_resource(
        self,
        resource_id: str,
        resource_type: str,
        raw_data: dict[str, Any],
        *,
        region: str | None = None,
        account: str | None = None,
        name: str | None = None,
        tags: dict[str, str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Resource:
        """
        Create a Resource object with common fields populated.

        Args:
            resource_id: Unique identifier for the resource
            resource_type: Type of resource
            raw_data: The raw resource data
            region: Cloud region
            account: Cloud account/subscription/project
            name: Human-readable name
            tags: Resource tags
            metadata: Additional metadata

        Returns:
            Resource object
        """
        return Resource(
            id=resource_id,
            type=resource_type,
            provider=self.metadata.platform,
            raw_data=raw_data,
            region=region,
            account=account,
            name=name,
            tags=tags or {},
            metadata=metadata or {},
            collected_at=datetime.now(timezone.utc),
        )


class CollectorRegistry:
    """
    Registry for discovering and instantiating collectors.
    """

    def __init__(self) -> None:
        self._collectors: dict[str, type[BaseCollector]] = {}

    def register(
        self,
        collector_class: type[BaseCollector],
        *,
        name: str | None = None,
    ) -> None:
        """
        Register a collector class.

        Args:
            collector_class: The collector class to register
            name: Optional override name (defaults to metadata.platform)
        """
        key = name or collector_class.metadata.platform
        self._collectors[key] = collector_class
        logger.debug(f"Registered collector: {key}")

    def get(self, name: str) -> type[BaseCollector] | None:
        """Get a collector class by name."""
        return self._collectors.get(name)

    def create(self, name: str, **kwargs: Any) -> BaseCollector:
        """
        Create a collector instance.

        Args:
            name: Collector name
            **kwargs: Arguments to pass to collector constructor

        Returns:
            Collector instance

        Raises:
            KeyError: If collector not found
        """
        collector_class = self._collectors.get(name)
        if not collector_class:
            available = ", ".join(self._collectors.keys())
            raise KeyError(
                f"Collector '{name}' not found. Available: {available}"
            )
        return collector_class(**kwargs)

    def list_collectors(
        self,
        *,
        mode: CollectorMode | None = None,
    ) -> list[CollectorMetadata]:
        """
        List available collectors.

        Args:
            mode: Filter by collector mode

        Returns:
            List of collector metadata
        """
        results = []
        for collector_class in self._collectors.values():
            meta = collector_class.metadata
            if mode is None or meta.mode == mode or meta.mode == CollectorMode.BOTH:
                results.append(meta)
        return results

    def list_names(self) -> list[str]:
        """Get list of registered collector names."""
        return list(self._collectors.keys())


# Global registry instance
collector_registry = CollectorRegistry()


def register_collector(
    name: str | None = None,
) -> Callable[[type[BaseCollector]], type[BaseCollector]]:
    """
    Decorator to register a collector class.

    Usage:
        @register_collector()
        class AWSCollector(BaseCollector):
            metadata = CollectorMetadata(platform="aws", ...)
    """

    def decorator(cls: type[BaseCollector]) -> type[BaseCollector]:
        collector_registry.register(cls, name=name)
        return cls

    return decorator
