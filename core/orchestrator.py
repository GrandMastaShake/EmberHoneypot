"""
HoneypotOrchestrator -- Spins up and tears down honeypot instances.

Stub implementation for Track 2c integration testing.
Full implementation in Track 2a.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from ember_honeypot.models import DecoyPersona, HoneypotInstance, HoneypotType, InstanceStatus, InstanceMetrics

logger = logging.getLogger(__name__)

# -- Defaults ------------------------------------------------------------

DEFAULT_MAX_INSTANCES: int = 100
DEFAULT_MAX_INTERACTIONS_PER_INSTANCE: int = 10_000


class HoneypotOrchestrator:
    """Manages honeypot container lifecycle."""

    def __init__(
        self,
        max_instances: int = DEFAULT_MAX_INSTANCES,
        max_interactions_per_instance: int = DEFAULT_MAX_INTERACTIONS_PER_INSTANCE,
    ) -> None:
        self._max_instances = max(max_instances, 1)
        self._max_interactions = max(max_interactions_per_instance, 1)
        # OrderedDict used as LRU cache -- oldest touched items are at the front
        self._instances: OrderedDict[UUID, HoneypotInstance] = OrderedDict()
        self._interaction_counts: dict[UUID, int] = {}

    async def create_instance(
        self,
        service_type: HoneypotType,
        persona: DecoyPersona,
        network_zone: str = "dmz",
        duration_minutes: int = 60,
    ) -> HoneypotInstance:
        # Enforce max instance limit with LRU eviction
        if len(self._instances) >= self._max_instances:
            # Evict oldest instance (LRU)
            oldest_id, oldest = self._instances.popitem(last=False)
            self._interaction_counts.pop(oldest_id, None)
            logger.warning(
                "LRU evicted oldest instance %s to make room (limit=%d)",
                oldest_id,
                self._max_instances,
            )

        instance = HoneypotInstance(
            id=uuid4(),
            type=service_type,
            status=InstanceStatus.ACTIVE,
            persona=persona,
            network_zone=network_zone,
            exposed_ports=self._default_ports(service_type),
            container_id=f"hp_{uuid4().hex[:12]}",
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=duration_minutes),
            metrics=InstanceMetrics(),
        )
        self._instances[instance.id] = instance
        self._interaction_counts[instance.id] = 0
        self._response_delay("medium")
        logger.info("Created %s honeypot %s", service_type.value, instance.id)
        return instance

    async def destroy_instance(self, instance_id: UUID) -> bool:
        """Destroy a honeypot instance. Returns True if existed, False otherwise."""
        start = time.monotonic()
        existed = False

        try:
            if instance_id in self._instances:
                self._instances[instance_id].status = InstanceStatus.DESTROYED
                del self._instances[instance_id]
                self._interaction_counts.pop(instance_id, None)
                existed = True
                logger.info("Destroyed honeypot %s", instance_id)
        except KeyError:
            pass

        # Constant-time padding: ensure both paths take ~same time
        elapsed = time.monotonic() - start
        if elapsed < 0.005:  # 5ms minimum
            await asyncio.sleep(0.005 - elapsed)

        return existed

    async def list_instances(
        self, status: InstanceStatus | None = None
    ) -> list[HoneypotInstance]:
        instances = list(self._instances.values())
        if status:
            instances = [i for i in instances if i.status == status]
        self._response_delay("low")
        return instances

    # -- Interaction Log Cap -----------------------------------------------

    async def log_interaction(self, instance_id: UUID) -> bool:
        """Record an interaction for *instance_id*, rotating old logs when cap is hit.

        Returns:
            True if the log was accepted, False if the cap was reached.
        """
        current = self._interaction_counts.get(instance_id, 0)
        if current >= self._max_interactions:
            logger.warning(
                "Interaction cap reached for %s (%d); rotating old logs",
                instance_id,
                self._max_interactions,
            )
            # Rotate: reset counter (in a real system, persist then flush)
            self._interaction_counts[instance_id] = 0
            return False
        self._interaction_counts[instance_id] = current + 1
        # Touch LRU
        if instance_id in self._instances:
            self._instances.move_to_end(instance_id)
        return True

    async def rotate_persona(self, instance_id: UUID, new_persona: DecoyPersona) -> None:
        if instance_id in self._instances:
            self._instances[instance_id].persona = new_persona
            # Touch LRU
            self._instances.move_to_end(instance_id)
            self._response_delay("low")
            logger.info("Rotated persona on honeypot %s", instance_id)

    async def get_instance(self, instance_id: UUID) -> HoneypotInstance | None:
        start = time.monotonic()
        result = None

        try:
            result = self._instances.get(instance_id)
            if result is not None:
                # Touch LRU on access
                self._instances.move_to_end(instance_id)
        except Exception:
            pass

        # Constant-time padding: ensure both paths take ~same time
        elapsed = time.monotonic() - start
        if elapsed < 0.003:  # 3ms minimum
            await asyncio.sleep(0.003 - elapsed)

        return result

    # -- Health Check --

    async def health_check(self) -> dict:
        """Return health status of the orchestrator.

        Returns:
            Dict with keys: healthy (bool), instance_count,
            max_instances, max_interactions_per_instance,
            detail, component name.
        """
        try:
            instance_count = len(self._instances)
            return {
                "healthy": True,
                "name": "orchestrator",
                "instance_count": instance_count,
                "max_instances": self._max_instances,
                "max_interactions_per_instance": self._max_interactions,
                "detail": (
                    f"Managing {instance_count}/{self._max_instances} instances, "
                    f"interaction cap={self._max_interactions}"
                ),
            }
        except Exception as exc:
            return {
                "healthy": False,
                "name": "orchestrator",
                "instance_count": 0,
                "max_instances": getattr(self, "_max_instances", DEFAULT_MAX_INSTANCES),
                "max_interactions_per_instance": getattr(self, "_max_interactions", DEFAULT_MAX_INTERACTIONS_PER_INSTANCE),
                "detail": f"Orchestrator check failed: {exc}",
            }

    # -- Helpers -----------------------------------------------------------

    @staticmethod
    def _realistic_delay(base: float = 0.1, sigma: float = 0.5) -> float:
        """Log-normal delay matching real system response times.

        Real systems have: fast mode (~50ms), slow tail (up to 2s).
        Log-normal: mean = base * exp(sigma^2/2), right-skewed.
        """
        delay = base * random.lognormvariate(0, sigma)
        return min(delay, 2.0)  # Cap at 2 seconds

    @staticmethod
    async def _response_delay(complexity: str = "low") -> None:  # noqa: RUF029
        """Apply realistic timing jitter to responses (async-safe).

        Uses ``await asyncio.sleep()`` to avoid blocking the event loop.
        """
        base_map = {
            "ssh_handshake": 0.15,
            "command": 0.05,
            "file_listing": 0.08,
            "auth_check": 0.03,
            "low": 0.05,
            "medium": 0.08,
            "high": 0.15,
        }
        base = base_map.get(complexity, 0.05)
        await asyncio.sleep(HoneypotOrchestrator._realistic_delay(base=base, sigma=0.8))

    @staticmethod
    def _validate_timing_distribution(samples: list[float]) -> dict:
        """Validate that timing samples don't look perfectly uniform."""
        import statistics
        if len(samples) < 10:
            return {"valid": False, "reason": "need more samples"}

        mean = statistics.mean(samples)
        stdev = statistics.stdev(samples) if len(samples) > 1 else 0
        cv = stdev / mean if mean > 0 else 0

        # Log-normal should have CV > 0.5
        return {
            "valid": cv > 0.5,
            "cv": round(cv, 3),
            "mean_ms": round(mean * 1000, 1),
        }

    @staticmethod
    def _default_ports(service_type: HoneypotType) -> list[int]:
        ports = {
            HoneypotType.SSH: [2222],
            HoneypotType.HTTP: [8080, 8443],
            HoneypotType.FTP: [2121],
            HoneypotType.DATABASE: [5432, 3306],
        }
        return ports.get(service_type, [8080])
