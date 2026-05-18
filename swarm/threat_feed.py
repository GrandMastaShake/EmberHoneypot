"""
ThreatFeed -- In-memory pub/sub threat feed for MVP, Redis-compatible for Phase 2.

Provides real-time bidirectional threat intelligence sharing:
- Subscribers register callbacks for threat updates
- Publishers broadcast new threats to all subscribers
- Recent threats are stored in a rolling buffer for replay
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ThreatSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(str, Enum):
    MALWARE = "malware"
    INTRUSION = "intrusion"
    RECON = "recon"
    EXPLOIT = "exploit"
    C2 = "c2"
    DATA_EXFIL = "data_exfil"
    LATERAL_MOVEMENT = "lateral_movement"


class ThreatUpdate(BaseModel):
    """A single threat update entry broadcast through the feed."""

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: ThreatSeverity = ThreatSeverity.LOW
    category: ThreatCategory = ThreatCategory.RECON
    source_ip: str = ""
    description: str = ""
    iocs: list[str] = Field(default_factory=list)
    ttps: list[str] = Field(default_factory=list)
    honeypot_id: UUID | None = None
    session_id: UUID | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# ThreatFeed
# ---------------------------------------------------------------------------


class ThreatFeed:
    """In-memory pub/sub threat intelligence feed.

    MVP: Pure in-memory implementation using asyncio callbacks.
    Phase 2: Redis-backed with persistence and cross-instance sync.
    """

    def __init__(self, max_history: int = 10000, redis_url: str | None = None) -> None:
        self.max_history = max_history
        self.redis_url = redis_url
        self._subscribers: list[Callable[[ThreatUpdate], Awaitable[None]]] = []
        self._history: deque[ThreatUpdate] = deque(maxlen=max_history)
        self._lock = asyncio.Lock()
        self._total_published = 0
        self._total_subscribers_served = 0

    # -- Subscription management -----------------------------------------------

    def subscribe(self, callback: Callable[[ThreatUpdate], Awaitable[None]]) -> None:
        """Register a callback to receive all future threat updates.

        The callback must be async and accept a single ThreatUpdate argument.
        Callbacks are fire-and-forget — exceptions are logged but not propagated.
        """
        self._subscribers.append(callback)
        logger.debug("New threat feed subscriber registered (total: %d)", len(self._subscribers))

    def unsubscribe(self, callback: Callable[[ThreatUpdate], Awaitable[None]]) -> bool:
        """Remove a previously registered callback.

        Returns True if the callback was found and removed.
        """
        if callback in self._subscribers:
            self._subscribers.remove(callback)
            logger.debug("Threat feed subscriber removed (total: %d)", len(self._subscribers))
            return True
        return False

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    # -- Publishing ------------------------------------------------------------

    async def publish(self, threat: ThreatUpdate) -> None:
        """Broadcast a new threat update to all subscribers.

        The threat is also stored in the rolling history buffer.
        Subscribers are called concurrently via asyncio.gather.
        """
        async with self._lock:
            self._history.append(threat)
            self._total_published += 1

        if not self._subscribers:
            return

        # Call all subscribers concurrently
        results = await asyncio.gather(
            *[self._safe_notify(cb, threat) for cb in self._subscribers],
            return_exceptions=True,
        )

        # Log any failures but don't propagate
        for idx, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning("Subscriber %d notification failed: %s", idx, result)

    async def _safe_notify(
        self,
        callback: Callable[[ThreatUpdate], Awaitable[None]],
        threat: ThreatUpdate,
    ) -> None:
        """Safely notify a single subscriber, catching all exceptions."""
        try:
            await callback(threat)
            self._total_subscribers_served += 1
        except Exception:
            logger.exception("Threat feed subscriber error")
            raise  # Will be caught by gather's return_exceptions

    # -- History / query -------------------------------------------------------

    def get_recent(self, limit: int = 100) -> list[ThreatUpdate]:
        """Retrieve the most recent threat updates from the rolling buffer.

        Args:
            limit: Maximum number of threats to return (default 100).

        Returns:
            List of ThreatUpdate, newest first.
        """
        history_list = list(self._history)
        return history_list[-limit:][::-1] if limit < len(history_list) else history_list[::-1]

    def get_by_severity(self, severity: ThreatSeverity, limit: int = 100) -> list[ThreatUpdate]:
        """Filter history by severity level."""
        filtered = [t for t in self._history if t.severity == severity]
        return filtered[-limit:][::-1] if limit < len(filtered) else filtered[::-1]

    def get_by_ip(self, source_ip: str) -> list[ThreatUpdate]:
        """Get all threat updates related to a specific source IP."""
        return [t for t in self._history if t.source_ip == source_ip][::-1]

    def get_stats(self) -> dict[str, Any]:
        """Return feed statistics for monitoring."""
        severities: dict[str, int] = {}
        categories: dict[str, int] = {}
        for t in self._history:
            severities[t.severity.value] = severities.get(t.severity.value, 0) + 1
            categories[t.category.value] = categories.get(t.category.value, 0) + 1

        return {
            "total_published": self._total_published,
            "buffer_size": len(self._history),
            "max_buffer": self.max_history,
            "subscriber_count": len(self._subscribers),
            "subscribers_served": self._total_subscribers_served,
            "severity_breakdown": severities,
            "category_breakdown": categories,
        }

    # -- Phase 2: Redis compatibility -----------------------------------------

    async def connect_redis(self, url: str) -> bool:
        """Connect to Redis for persistent pub/sub (Phase 2).

        Returns True if Redis connection succeeded.
        """
        self.redis_url = url
        logger.info("Redis pub/sub configured at %s (Phase 2 — not yet active)", url)
        return False  # MVP: Redis not active

    async def flush_to_redis(self) -> int:
        """Flush current buffer to Redis for persistence (Phase 2).

        Returns number of items flushed.
        """
        logger.info("Redis flush skipped (Phase 2)")
        return 0
