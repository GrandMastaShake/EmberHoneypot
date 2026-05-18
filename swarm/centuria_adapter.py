"""
CenturiaAdapter -- Bridge between EmberHoneypot and the Centuria swarm of 101 agents.

Stub implementation for MVP (Phase 1). Actual swarm connection is Phase 2.
Provides mock responses that simulate a healthy swarm connection.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from ember_honeypot.models import DecoyPersona, IOC, TTPRecord

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ThreatIntel(BaseModel):
    """Structured threat intelligence report for swarm submission."""

    id: UUID = Field(default_factory=uuid4)
    attacker_ip: str
    ttps: list[TTPRecord] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    threat_score: int = Field(default=0, ge=0, le=100)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    raw_indicators: list[str] = Field(default_factory=list)
    session_id: UUID | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)


class CollectiveMemory(BaseModel):
    """Shared swarm knowledge about a specific attacker or threat."""

    attacker_ip: str
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    seen_by_agents: list[str] = Field(default_factory=list)
    aggregate_threat_score: int = Field(default=0, ge=0, le=100)
    known_ttps: list[TTPRecord] = Field(default_factory=list)
    known_iocs: list[IOC] = Field(default_factory=list)
    swarm_consensus: str = "unknown"  # known_threat | suspicious | unknown | benign
    recommendation: str = "monitor"
    metadata: dict[str, Any] = Field(default_factory=dict)


class SwarmHealth(BaseModel):
    """Health status of the Centuria swarm connection."""

    connected: bool = False
    agents_online: int = 0
    total_agents: int = 101
    latency_ms: float = 0.0
    last_heartbeat: datetime | None = None
    queued_intel_count: int = 0


# ---------------------------------------------------------------------------
# CenturiaAdapter
# ---------------------------------------------------------------------------


class CenturiaAdapter:
    """Bridge between honeypot intelligence and Centuria swarm of 101 agents.

    MVP implementation uses an in-memory mock with realistic responses.
    Phase 2 will connect to the actual swarm API via gRPC/WebSocket.
    """

    def __init__(
        self,
        endpoint: str = "http://centuria-swarm:8080",
        api_key: str | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.endpoint = endpoint
        self.api_key = api_key
        self.timeout = timeout
        self._connected = False
        self._queued_intel: list[ThreatIntel] = []
        self._queued_iocs: list[IOC] = []
        self._collective_memory: dict[str, CollectiveMemory] = {}
        self._callbacks: list[Callable[[dict], Awaitable[None]]] = []
        self._agents_online = 0
        self._latency_ms = 0.0
        self._last_heartbeat: datetime | None = None

    # -- Connection management ------------------------------------------------

    async def connect(self) -> bool:
        """Connect to the Centuria swarm.

        Returns True if connection succeeded (or mock is active).
        """
        logger.info("Connecting to Centuria swarm at %s", self.endpoint)
        await asyncio.sleep(0.01)  # Simulate network latency
        self._connected = True
        self._agents_online = 87  # Mock: 87 of 101 agents online
        self._latency_ms = 12.5
        self._last_heartbeat = datetime.now(timezone.utc)
        logger.info("Connected to swarm: %d/101 agents online", self._agents_online)
        return True

    async def disconnect(self) -> None:
        """Gracefully disconnect from the swarm."""
        self._connected = False
        self._agents_online = 0
        self._last_heartbeat = None
        logger.info("Disconnected from Centuria swarm")

    @property
    def connected(self) -> bool:
        return self._connected

    def health(self) -> SwarmHealth:
        """Return current swarm health status."""
        return SwarmHealth(
            connected=self._connected,
            agents_online=self._agents_online,
            total_agents=101,
            latency_ms=self._latency_ms,
            last_heartbeat=self._last_heartbeat,
            queued_intel_count=len(self._queued_intel),
        )

    # -- Intelligence sharing -------------------------------------------------

    async def submit_threat_intel(self, intel: ThreatIntel) -> bool:
        """Share threat intelligence with the swarm.

        Returns True if the intel was accepted (or queued for later).
        If swarm is unreachable, intel is queued for batch submission.
        """
        if not self._connected:
            self._queued_intel.append(intel)
            logger.warning("Swarm offline — intel queued (%d items)", len(self._queued_intel))
            return True  # Queued, not lost

        await asyncio.sleep(0.005)  # Simulate API latency
        logger.info(
            "Submitted threat intel for %s (score=%d) to swarm",
            intel.attacker_ip,
            intel.threat_score,
        )

        # Update collective memory
        if intel.attacker_ip in self._collective_memory:
            mem = self._collective_memory[intel.attacker_ip]
            mem.last_seen = datetime.now(timezone.utc)
            mem.known_ttps.extend(intel.ttps)
            mem.known_iocs.extend(intel.iocs)
            mem.aggregate_threat_score = max(
                mem.aggregate_threat_score, intel.threat_score
            )
        else:
            self._collective_memory[intel.attacker_ip] = CollectiveMemory(
                attacker_ip=intel.attacker_ip,
                known_ttps=intel.ttps,
                known_iocs=intel.iocs,
                aggregate_threat_score=intel.threat_score,
                seen_by_agents=["honeypot_001"],
            )

        # Notify subscribers
        await self._notify_subscribers({
            "event": "new_intel",
            "attacker_ip": intel.attacker_ip,
            "threat_score": intel.threat_score,
        })

        return True

    async def get_collective_memory(self, attacker_ip: str) -> CollectiveMemory | None:
        """Retrieve swarm collective knowledge about an attacker IP.

        Returns CollectiveMemory if known, None if no data exists.
        """
        if attacker_ip in self._collective_memory:
            return self._collective_memory[attacker_ip]

        # Mock: generate synthetic collective memory for unknown IPs
        # that look like they've been seen before
        if self._connected:
            await asyncio.sleep(0.003)
            # Return a mock "unknown" entry — the swarm has no data yet
            return None

        return None

    # -- IOC broadcasting -----------------------------------------------------

    async def broadcast_ioc(self, ioc: IOC) -> bool:
        """Share an Indicator of Compromise globally across the swarm.

        Returns True if broadcast succeeded or was queued.
        """
        if not self._connected:
            self._queued_iocs.append(ioc)
            logger.warning("Swarm offline — IOC queued (%d items)", len(self._queued_iocs))
            return True

        await asyncio.sleep(0.003)
        logger.info(
            "Broadcast IOC: %s (%s) to swarm",
            ioc.value[:50],
            ioc.ioc_type.value,
        )
        return True

    # -- Reinforcement requests -----------------------------------------------

    async def request_reinforcement(self, persona: DecoyPersona) -> bool:
        """Request swarm to deploy adaptive defense for a specific persona.

        Returns True if the swarm acknowledged the request.
        """
        if not self._connected:
            logger.warning("Swarm offline — reinforcement request dropped")
            return False

        await asyncio.sleep(0.008)
        logger.info(
            "Requested reinforcement for persona %s (role=%s)",
            persona.id,
            persona.role,
        )
        return True

    # -- Internal -------------------------------------------------------------

    async def _notify_subscribers(self, event: dict) -> None:
        """Notify all registered callbacks of a swarm event."""
        for callback in self._callbacks:
            try:
                await callback(event)
            except Exception:
                logger.exception("Swarm callback error — continuing")

    def _memory_key(self, attacker_ip: str) -> str:
        """Generate a deterministic key for collective memory lookups."""
        retu