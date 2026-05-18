"""
Structured Logging Configuration for SecureNet.

Provides JSON-format log records for log aggregation systems (ELK, Loki,
CloudWatch) with correlation ID propagation via contextvars.

Usage:
    from ember_honeypot.monitoring.logging_config import configure_logging
    configure_logging(level="INFO", json_format=True)

    logger = logging.getLogger("secure_net.core")
    logger.info("Server started", extra={"instance_id": "abc-123"})
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import sys
import traceback
from datetime import datetime, timezone
from typing import Any



# ---------------------------------------------------------------------------
# Context-local correlation ID
# ---------------------------------------------------------------------------

_cid_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id", default=None
)
_correlation_ctx: dict[int, str | None] = {}


def get_correlation_id() -> str | None:
    """Return the correlation ID for the current async context.

    Uses :class:`contextvars.ContextVar` for safe async propagation,
    falling back to thread-local storage when needed.
    """
    try:
        return _cid_var.get()
    except Exception:
        import threading

        return _correlation_ctx.get(threading.current_thread().ident, None)


def set_correlation_id(cid: str | None) -> None:
    """Set correlation ID for the current execution context."""
    try:
        _cid_var.set(cid)
    except Exception:
        import threading

        _correlation_ctx[threading.current_thread().ident] = cid


# ---------------------------------------------------------------------------
# Structured JSON Formatter
# ---------------------------------------------------------------------------


class StructuredLogFormatter(logging.Formatter):
    """JSON formatter for structured logging.

    Each log record is emitted as a single line of JSON containing:
    timestamp, level, logger name, message, source location, correlation ID,
    and any extra fields.

    Example output::

        {"timestamp": "2025-01-15T09:23:47.123456+00:00", "level": "INFO",
         "logger": "secure_net.core", "message": "Server spawned",
         "correlation_id": "abc-123", "extra": {"instance_id": "hp-1"}}
    """

    # Fields to include in every log record
    DEFAULT_FIELDS = [
        "timestamp",
        "level",
        "logger",
        "message",
        "module",
        "function",
        "line",
        "thread",
        "correlation_id",
        "extra",
    ]

    def __init__(
        self,
        fields: list[str] | None = None,
        datefmt: str | None = None,
        indent: int | None = None,
    ) -> None:
        super().__init__(datefmt=datefmt)
        self.fields = fields or self.DEFAULT_FIELDS
        self.indent = indent  # None = compact single-line

    def format(self, record: logging.LogRecord) -> str:
        """Format *record* as a JSON string."""
        payload: dict[str, Any] = {}

        if "timestamp" in self.fields:
            payload["timestamp"] = datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat()

        if "level" in self.fields:
            payload["level"] = record.levelname

        if "logger" in self.fields:
            payload["logger"] = record.name

        if "message" in self.fields:
            payload["message"] = record.getMessage()

        if "module" in self.fields:
            payload["module"] = record.module

        if "function" in self.fields:
            payload["function"] = record.funcName

        if "line" in self.fields:
            payload["line"] = record.lineno

        if "thread" in self.fields:
            payload["thread"] = record.thread

        if "correlation_id" in self.fields:
            # Check record extra attrs first, then context
            cid = getattr(record, "correlation_id", None) or get_correlation_id()
            if cid:
                payload["correlation_id"] = cid

        if "extra" in self.fields:
            extra = getattr(record, "extra", {})
            if hasattr(record, "correlation_id"):
                extra = {k: v for k, v in extra.items() if k != "correlation_id"}
            if extra:
                payload["extra"] = extra

        # Exception info
        if record.exc_info and record.exc_info[0] is not None:
            payload["exception"] = self._format_exception(record)

        # Stack info
        if record.stack_info:
            payload["stack"] = record.stack_info

        return json.dumps(payload, default=str, indent=self.indent)

    @staticmethod
    def _format_exception(record: logging.LogRecord) -> dict[str, str]:
        """Format exception info as a dict."""
        if not record.exc_info:
            return {}
        exc_type, exc_value, exc_tb = record.exc_info
        return {
            "type": exc_type.__name__ if exc_type else "Unknown",
            "message": str(exc_value) if exc_value else "",
            "traceback": "".join(traceback.format_exception(*record.exc_info)),
        }


# ---------------------------------------------------------------------------
# Human-readable formatter (fallback)
# ---------------------------------------------------------------------------


class HumanReadableFormatter(logging.Formatter):
    """Pretty console formatter for local development.

    Output::

        2025-01-15 09:23:47 [INFO] secure_net.core: Server spawned
                                     -- correlation_id=abc-123 instance_id=hp-1
    """

    COLORS = {
        "DEBUG": "\033[36m",  # cyan
        "INFO": "\033[32m",  # green
        "WARNING": "\033[33m",  # yellow
        "ERROR": "\033[31m",  # red
        "CRITICAL": "\033[35m",  # magenta
        "RESET": "\033[0m",
    }

    def __init__(self, use_color: bool = True) -> None:
        super().__init__()
        self.use_color = use_color and sys.stdout.isatty()

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        level = record.levelname
        color = self.COLORS.get(level, "") if self.use_color else ""
        reset = self.COLORS["RESET"] if self.use_color else ""

        msg = record.getMessage()
        line = f"{ts} [{color}{level}{reset}] {record.name}: {msg}"

        # Append correlation id and extra if present
        extras: list[str] = []
        cid = getattr(record, "correlation_id", None) or get_correlation_id()
        if cid:
            extras.append(f"correlation_id={cid}")
        extra = getattr(record, "extra", {})
        for k, v in extra.items():
            extras.append(f"{k}={v}")

        if extras:
            indent = " " * 29 + "-- "
            line += "\n" + indent + " ".join(extras)

        # Exception
        if record.exc_info and record.exc_info[0] is not None:
            line += "\n" + "".join(traceback.format_exception(*record.exc_info))

        return line


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def configure_logging(
    level: str = "INFO",
    json_format: bool = True,
    log_file: str | None = None,
    filters: list[str] | None = None,
) -> None:
    """Configure structured logging for production.

    Args:
        level: Root log level (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``).
        json_format: Emit JSON when ``True``; pretty human-readable otherwise.
        log_file: Optional path to write logs (in addition to stderr).
        filters: List of logger names to silence (e.g. ``["uvicorn.access"]``).
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Clear existing handlers to avoid duplicate output
    root.handlers.clear()

    formatter: logging.Formatter
    if json_format:
        formatter = StructuredLogFormatter()
    else:
        formatter = HumanReadableFormatter()

    # Stderr handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    # Optional file handler (JSON always)
    if log_file:
        safe_file = os.path.basename(log_file) if '..' in log_file or '/' in log_file else log_file
        log_dir = "/var/log/secure_net"
        file_handler = logging.FileHandler(f"{log_dir}/{safe_file}")
        file_handler.setFormatter(StructuredLogFormatter())
        root.addHandler(file_handler)

    # Silence noisy third-party loggers
    filters = filters or ["uvicorn.access", "asyncio"]
    for name in filters:
        logging.getLogger(name).setLevel(logging.WARNING)

    # Log the configuration
    logging.getLogger("secure_net.monitoring").info(
        "Logging configured",
        extra={"level": level, "json_format": json_format, "file": log_file},
    )


def get_logger(name: str) -> logging.Logger:
    """Get a named logger with SecureNet defaults applied."""
    return logging.getLogger(name)
