"""
InteractionLogger -- Captures every interaction at maximum fidelity.

Stub implementation for Track 2c integration testing.

Provides structured JSON logging with correlation ID support
following Corporeus Phase 6 monitoring patterns.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from ember_honeypot.models import InteractionLog, InteractionType, ParsedCommand


# ---------------------------------------------------------------------------
# Structured JSON Formatter
# ---------------------------------------------------------------------------

class StructuredLogFormatter(logging.Formatter):
    """JSON formatter for structured logging.

    Each log record is emitted as a single line of JSON containing:
    timestamp, level, logger name, message, source location, and
    correlation ID.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "thread": record.thread,
        }

        # Correlation ID
        cid = getattr(record, "correlation_id", None)
        if cid:
            payload["correlation_id"] = cid

        # Extra fields
        extra = getattr(record, "extra", {})
        if extra:
            payload["extra"] = extra

        # Exception info
        if record.exc_info and record.exc_info[0] is not None:
            import traceback

            exc_type, exc_value, _ = record.exc_info
            payload["exception"] = {
                "type": exc_type.__name__ if exc_type else "Unknown",
                "message": str(exc_value) if exc_value else "",
                "traceback": traceback.format_exc(),
            }

        return json.dumps(payload, default=str)


# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------


def configure_logging(level: str = "INFO", json_format: bool = True) -> logging.Logger:
    """Configure structured logging for the EmberHoneypot platform.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR).
        json_format: If True, use JSON formatting; otherwise human-readable.

    Returns:
        The root ember_honeypot logger instance.
    """
    root_logger = logging.getLogger("ember_honeypot")
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Avoid duplicate handlers on re-import
    if root_logger.handlers:
        root_logger.handlers.clear()

    handler = logging.StreamHandler()
    if json_format:
        handler.setFormatter(StructuredLogFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            )
        )
    root_logger.addHandler(handler)
    return root_logger


# Default module-level logger
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# InteractionLogger
# ---------------------------------------------------------------------------


class InteractionLogger:
    """Logs all attacker interactions."""

    def __init__(self) -> None:
        self._logs: dict[UUID, list[InteractionLog]] = defaultdict(list)
        self._all_logs: list[InteractionLog] = []
        self._sequence_counters: dict[UUID, int] = defaultdict(int)

    async def log_command(
        self,
        session_id: UUID,
        attacker_id: UUID,
        honeypot_id: UUID,
        command: str,
        output: str,
        timestamp: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> InteractionLog:
        self._sequence_counters[session_id] += 1
        log = InteractionLog(
            id=uuid4(),
            session_id=session_id,
            attacker_id=attacker_id,
            honeypot_id=honeypot_id,
            timestamp=timestamp or datetime.utcnow(),
            sequence_number=self._sequence_counters[session_id],
            interaction_type=InteractionType.COMMAND,
            raw_input=command,
            raw_output=output,
            parsed_command=self._parse_command(command),
            source_ip=metadata.get("source_ip", "") if metadata else "",
            source_port=metadata.get("source_port", 0) if metadata else 0,
        )
        self._logs[session_id].append(log)
        self._all_logs.append(log)
        return log

    async def log_login(
        self,
        session_id: UUID,
        attacker_id: UUID,
        honeypot_id: UUID,
        username: str,
        password: str,
        success: bool = False,
        source_ip: str = "",
    ) -> InteractionLog:
        self._sequence_counters[session_id] += 1
        log = InteractionLog(
            id=uuid4(),
            session_id=session_id,
            attacker_id=attacker_id,
            honeypot_id=honeypot_id,
            sequence_number=self._sequence_counters[session_id],
            interaction_type=InteractionType.LOGIN,
            raw_input=f"{username}:{password}",
            raw_output="Login successful" if success else "Access denied",
            source_ip=source_ip,
        )
        self._logs[session_id].append(log)
        self._all_logs.append(log)
        return log

    async def get_session_timeline(self, session_id: UUID) -> list[InteractionLog]:
        return list(self._logs.get(session_id, []))

    async def get_all_logs(self, limit: int = 1000) -> list[InteractionLog]:
        return self._all_logs[-limit:]

    def _parse_command(self, command: str) -> ParsedCommand | None:
        if not command:
            return None
        parts = command.strip().split()
        if not parts:
            return None
        return ParsedCommand(
            binary=parts[0],
            arguments=parts[1:],
        )

    # -- Monitoring / Health Check --

    async def health_check(self) -> dict[str, Any]:
        """Return health status of the interaction logger.

        Returns:
            Dict with keys: healthy (bool), log_count, session_count,
            last_log_at (or None).
        """
        return {
            "healthy": True,
            "log_count": len(self._all_logs),
            "session_count": len(self._logs),
            "last_log_at": (
                self._all_logs[-1].timestamp.isoformat() if self._all_logs else None
            ),
        }
