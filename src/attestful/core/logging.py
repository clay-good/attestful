"""
Logging configuration for Attestful.

Provides structured logging with support for JSON output, configurable levels,
and integration with Rich for console output.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from typing import Any

import orjson
from rich.console import Console
from rich.logging import RichHandler


# Default log format for file output
DEFAULT_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Module-level console for rich output
_console: Console | None = None
_configured: bool = False


def get_console() -> Console:
    """Get or create the Rich console instance."""
    global _console
    if _console is None:
        _console = Console(stderr=True)
    return _console


class JSONFormatter(logging.Formatter):
    """
    Format log records as JSON for structured logging.

    Useful for log aggregation systems like ELK, Splunk, or Datadog.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields
        if hasattr(record, "extra"):
            log_data["extra"] = record.extra

        # Add standard fields if present
        for field in ["platform", "check_id", "resource_id", "scan_id"]:
            if hasattr(record, field):
                log_data[field] = getattr(record, field)

        return orjson.dumps(log_data).decode("utf-8")


class AttestfulLogger(logging.LoggerAdapter):
    """
    Custom logger adapter that adds context to log messages.

    Supports adding persistent context that appears in all log messages.
    """

    def __init__(
        self,
        logger: logging.Logger,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(logger, extra or {})

    def process(
        self,
        msg: str,
        kwargs: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        # Merge adapter extra with call-time extra
        extra = {**self.extra, **kwargs.get("extra", {})}
        kwargs["extra"] = extra
        return msg, kwargs

    def with_context(self, **context: Any) -> AttestfulLogger:
        """Create a new logger with additional context."""
        new_extra = {**self.extra, **context}
        return AttestfulLogger(self.logger, new_extra)


def setup_logging(
    level: str | int = logging.INFO,
    *,
    json_output: bool = False,
    log_file: str | None = None,
    quiet: bool = False,
) -> None:
    """
    Configure logging for Attestful.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_output: Use JSON format for all output
        log_file: Optional file path to write logs
        quiet: Suppress console output (only write to file)
    """
    global _configured

    # Convert string level to int
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    # Get root attestful logger
    root_logger = logging.getLogger("attestful")
    root_logger.setLevel(level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Console handler
    if not quiet:
        if json_output:
            console_handler = logging.StreamHandler(sys.stderr)
            console_handler.setFormatter(JSONFormatter())
        else:
            console_handler = RichHandler(
                console=get_console(),
                show_time=True,
                show_path=False,
                rich_tracebacks=True,
                tracebacks_show_locals=True,
            )
        console_handler.setLevel(level)
        root_logger.addHandler(console_handler)

    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        if json_output:
            file_handler.setFormatter(JSONFormatter())
        else:
            file_handler.setFormatter(
                logging.Formatter(DEFAULT_FORMAT, DEFAULT_DATE_FORMAT)
            )
        file_handler.setLevel(level)
        root_logger.addHandler(file_handler)

    _configured = True


def get_logger(name: str, **context: Any) -> AttestfulLogger:
    """
    Get a logger with the given name.

    Args:
        name: Logger name (will be prefixed with 'attestful.')
        **context: Additional context to include in all log messages

    Returns:
        AttestfulLogger instance
    """
    global _configured

    # Auto-configure with defaults if not already done
    if not _configured:
        setup_logging()

    # Ensure name is under attestful namespace
    if not name.startswith("attestful."):
        name = f"attestful.{name}"

    logger = logging.getLogger(name)
    return AttestfulLogger(logger, context)


# Convenience function for quick debug logging
def debug(msg: str, **kwargs: Any) -> None:
    """Quick debug log."""
    get_logger("debug").debug(msg, extra=kwargs)


def info(msg: str, **kwargs: Any) -> None:
    """Quick info log."""
    get_logger("info").info(msg, extra=kwargs)


def warning(msg: str, **kwargs: Any) -> None:
    """Quick warning log."""
    get_logger("warning").warning(msg, extra=kwargs)


def error(msg: str, **kwargs: Any) -> None:
    """Quick error log."""
    get_logger("error").error(msg, extra=kwargs)
