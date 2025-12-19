"""
Collector optimization utilities for improved performance.

Provides exponential backoff, request caching, and batch processing utilities
for handling rate limits, caching API responses, and processing items in parallel.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable, TypeVar

from attestful.core.logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


class ExponentialBackoff:
    """
    Exponential backoff strategy for handling rate limits and transient failures.

    Implements exponential backoff with jitter to avoid thundering herd problem.
    """

    def __init__(
        self,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_retries: int = 5,
        exponential_base: float = 2.0,
        jitter: bool = True,
    ):
        """
        Initialize exponential backoff strategy.

        Args:
            base_delay: Initial delay in seconds
            max_delay: Maximum delay in seconds
            max_retries: Maximum number of retries
            exponential_base: Base for exponential calculation
            jitter: Whether to add random jitter to delays
        """
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self.exponential_base = exponential_base
        self.jitter = jitter
        self.attempt = 0

    def get_delay(self) -> float:
        """Calculate delay for current attempt."""
        delay = min(
            self.base_delay * (self.exponential_base**self.attempt),
            self.max_delay,
        )

        if self.jitter:
            # Add jitter: random value between 0 and delay
            delay = random.uniform(0, delay)

        return delay

    def should_retry(self) -> bool:
        """Check if should retry based on attempt count."""
        return self.attempt < self.max_retries

    async def sleep(self) -> None:
        """Sleep for calculated delay and increment attempt counter."""
        delay = self.get_delay()
        logger.debug(
            "exponential_backoff_sleep",
            extra={
                "delay_seconds": round(delay, 2),
                "attempt": self.attempt + 1,
                "max_retries": self.max_retries,
            },
        )
        await asyncio.sleep(delay)
        self.attempt += 1

    def reset(self) -> None:
        """Reset attempt counter."""
        self.attempt = 0


def with_exponential_backoff(
    retryable_exceptions: tuple[type, ...] = (Exception,),
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    max_retries: int = 5,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator to add exponential backoff to async functions.

    Args:
        retryable_exceptions: Tuple of exception types to retry on
        base_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
        max_retries: Maximum number of retries

    Example:
        @with_exponential_backoff(
            retryable_exceptions=(ClientError,),
            max_retries=3
        )
        async def make_api_call():
            return await client.get_data()
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            backoff = ExponentialBackoff(
                base_delay=base_delay,
                max_delay=max_delay,
                max_retries=max_retries,
            )

            last_exception: Exception | None = None
            while True:
                try:
                    return await func(*args, **kwargs)
                except retryable_exceptions as e:
                    last_exception = e

                    # Check if this is a rate limit error
                    error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
                    is_rate_limit = error_code in [
                        "Throttling",
                        "TooManyRequests",
                        "RequestLimitExceeded",
                        "ThrottlingException",
                        "ProvisionedThroughputExceededException",
                    ]

                    if is_rate_limit:
                        logger.warning(
                            "rate_limit_hit",
                            extra={"function": func.__name__, "error_code": error_code},
                        )

                    if not backoff.should_retry():
                        logger.error(
                            "max_retries_exceeded",
                            extra={
                                "function": func.__name__,
                                "error": str(e),
                                "attempts": backoff.attempt,
                            },
                        )
                        raise

                    await backoff.sleep()

            # Should never reach here, but just in case
            if last_exception:
                raise last_exception

        return wrapper  # type: ignore[return-value]

    return decorator


class RequestCache:
    """
    Simple in-memory cache for API requests with TTL support.

    Caches request results to avoid redundant API calls within a time window.
    """

    def __init__(self, default_ttl: int = 300):
        """
        Initialize request cache.

        Args:
            default_ttl: Default time-to-live in seconds (default: 5 minutes)
        """
        self.default_ttl = default_ttl
        self._cache: dict[str, tuple[Any, datetime]] = {}
        self._hits = 0
        self._misses = 0

    def _make_key(self, *args: Any, **kwargs: Any) -> str:
        """Generate cache key from function arguments."""
        # Create a stable string representation
        key_data = {"args": args, "kwargs": sorted(kwargs.items())}
        key_str = json.dumps(key_data, sort_keys=True, default=str)
        return hashlib.sha256(key_str.encode()).hexdigest()

    def get(self, key: str) -> Any | None:
        """Get value from cache if not expired."""
        if key in self._cache:
            value, expires_at = self._cache[key]
            if datetime.now(timezone.utc) < expires_at:
                self._hits += 1
                return value
            else:
                # Expired, remove from cache
                del self._cache[key]

        self._misses += 1
        return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Set value in cache with TTL."""
        if ttl is None:
            ttl = self.default_ttl

        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        self._cache[key] = (value, expires_at)

    def clear(self) -> None:
        """Clear all cached values."""
        self._cache.clear()
        self._hits = 0
        self._misses = 0

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0

        return {
            "hits": self._hits,
            "misses": self._misses,
            "total_requests": total,
            "hit_rate_percent": round(hit_rate, 2),
            "cached_items": len(self._cache),
        }


def with_request_cache(
    cache: RequestCache, ttl: int | None = None
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator to add request caching to async functions.

    Args:
        cache: RequestCache instance to use
        ttl: Time-to-live in seconds (uses cache default if None)

    Example:
        cache = RequestCache(default_ttl=300)

        @with_request_cache(cache, ttl=600)
        async def get_user(user_id: str):
            return await api.get_user(user_id)
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            # Generate cache key
            cache_key = cache._make_key(func.__name__, *args, **kwargs)

            # Check cache
            cached_value = cache.get(cache_key)
            if cached_value is not None:
                logger.debug(
                    "cache_hit",
                    extra={"function": func.__name__},
                )
                return cached_value

            # Cache miss - call function
            logger.debug(
                "cache_miss",
                extra={"function": func.__name__},
            )
            result = await func(*args, **kwargs)

            # Store in cache
            cache.set(cache_key, result, ttl)

            return result

        return wrapper  # type: ignore[return-value]

    return decorator


class BatchProcessor:
    """
    Utility for processing items in batches with concurrency control.

    Useful for processing large lists of resources with controlled parallelism.
    """

    @staticmethod
    async def process_batch(
        items: list[T],
        processor: Callable[[T], Any],
        batch_size: int = 10,
        max_concurrent: int = 5,
    ) -> list[Any]:
        """
        Process items in batches with concurrency control.

        Args:
            items: List of items to process
            processor: Async function to process each item
            batch_size: Number of items per batch
            max_concurrent: Maximum concurrent operations

        Returns:
            List of processed results
        """
        results: list[Any] = []
        semaphore = asyncio.Semaphore(max_concurrent)

        async def process_with_semaphore(item: T) -> Any:
            async with semaphore:
                return await processor(item)

        # Process in batches
        for i in range(0, len(items), batch_size):
            batch = items[i : i + batch_size]
            batch_results = await asyncio.gather(
                *[process_with_semaphore(item) for item in batch],
                return_exceptions=True,
            )
            results.extend(batch_results)

        return results

    @staticmethod
    async def process_with_progress(
        items: list[T],
        processor: Callable[[T], Any],
        batch_size: int = 10,
        max_concurrent: int = 5,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[Any]:
        """
        Process items in batches with progress reporting.

        Args:
            items: List of items to process
            processor: Async function to process each item
            batch_size: Number of items per batch
            max_concurrent: Maximum concurrent operations
            progress_callback: Callback function(completed, total)

        Returns:
            List of processed results
        """
        results: list[Any] = []
        semaphore = asyncio.Semaphore(max_concurrent)
        completed = 0
        total = len(items)

        async def process_with_semaphore(item: T) -> Any:
            nonlocal completed
            async with semaphore:
                result = await processor(item)
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)
                return result

        # Process in batches
        for i in range(0, len(items), batch_size):
            batch = items[i : i + batch_size]
            batch_results = await asyncio.gather(
                *[process_with_semaphore(item) for item in batch],
                return_exceptions=True,
            )
            results.extend(batch_results)

        return results
