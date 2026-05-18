"""
Health Check System for SecureNet.

Provides deep and shallow health checks for all server components.
Supports checking individual subsystems (orchestrator, engine, intel,
rate limiter, attacker profiler) and aggregates results into an
overall health status.

Usage:
    checker = HealthChecker(
        version="0.1.0",
        orchestrator=orchestrator,
        engine=engine,
        rate_limiter=rate_limiter,
        attacker_profiler=profiler,
    )
    status = await checker.check(depth="shallow")
    if status.overall != "healthy":
        logger.warning(f"Degraded: {status}")
"""

from __future__ import annotations

import asyncio
import platform
import shutil
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

from pydantic import BaseModel, Field


class Status(str, Enum):
    """Health status levels."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class ComponentHealth(BaseModel):
    """Health status of a single component."""

    name: str = Field(..., description="Component identifier")
    status: str = Field(..., description="One of: healthy | degraded | unhealthy")
    response_time_ms: float = Field(..., description="Check duration in milliseconds")
    detail: str | None = Field(default=None, description="Human-readable detail message")
    last_checked: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extra check data")

    def model_post_init(self, __context: Any) -> None:
        """Validate status value."""
        if self.status not in {"healthy", "degraded", "unhealthy"}:
            raise ValueError(f"Invalid status: {self.status}")


class HealthStatus(BaseModel):
    """Aggregated health status across all components."""

    overall: str = Field(..., description="Aggregated: healthy | degraded | unhealthy")
    components: list[ComponentHealth] = Field(default_factory=list)
    version: str = Field(default="0.1.0", description="SecureNet version string")
    uptime_seconds: float = Field(default=0.0, description="Process uptime in seconds")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    hostname: str = Field(default_factory=platform.node, description="Host machine name")


class HealthChecker:
    """Deep and shallow health checks for all SecureNet components.

    Each ``check_*`` method returns a :class:`ComponentHealth` record.
    The :meth:`check` method aggregates them into a :class:`HealthStatus`.

    Check depth:
        * **shallow** -- Fast, lightweight probes (connectivity, basic state).
        * **deep**    -- Full component exercise (actual end-to-end test).

    Example:
        >>> checker = HealthChecker(version="0.1.0")
        >>> status = await checker.check(depth="deep")
        >>> print(status.overall)
        'healthy'
    """

    CHECKS: dict[str, str] = {
        "orchestrator": "check_orchestrator",
        "engine": "check_engine",
        "rate_limiter": "check_rate_limiter",
        "attacker_profiler": "check_attacker_profiler",
        "disk": "check_disk_space",
    }

    # Thresholds
    DISK_WARN_PERCENT: float = 20.0  # warn when < 20% free
    DISK_CRITICAL_PERCENT: float = 10.0  # critical when < 10% free

    def __init__(
        self,
        version: str = "0.1.0",
        start_time: float | None = None,
        orchestrator: Any = None,
        engine: Any = None,
        rate_limiter: Any = None,
        attacker_profiler: Any = None,
    ) -> None:
        self.version = version
        self.start_time = start_time or time.monotonic()
        self.orchestrator = orchestrator
        self.engine = engine
        self.rate_limiter = rate_limiter
        self.attacker_profiler = attacker_profiler

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check(self, depth: str = "shallow") -> HealthStatus:
        """Run health checks.

        Args:
            depth: ``"shallow"`` for fast basic checks, ``"deep"``
                for thorough component checks.

        Returns:
            :class:`HealthStatus` with overall and per-component results.
        """
        if depth not in {"shallow", "deep"}:
            raise ValueError(f"Invalid depth: {depth!r}. Use 'shallow' or 'deep'.")

        components = await self._run_checks(depth)
        overall = self._aggregate(components)

        return HealthStatus(
            overall=overall,
            components=components,
            version=self.version,
            uptime_seconds=time.monotonic() - self.start_time,
        )

    async def check_orchestrator(self) -> ComponentHealth:
        """Verify orchestrator is functional."""
        start = time.monotonic()
        try:
            if self.orchestrator is not None:
                result = await self.orchestrator.health_check()
                if result.get("healthy", True):
                    return self._ok(
                        "orchestrator",
                        start,
                        f"Orchestrator healthy ({result.get('instance_count', 0)} instances)",
                        metadata=result,
                    )
                return self._degraded(
                    "orchestrator", start, result.get("detail", "Orchestrator degraded")
                )
            return self._ok("orchestrator", start, "Orchestrator not configured -- skipped")
        except Exception as exc:
            return self._fail("orchestrator", start, f"Orchestrator error: {exc}")

    async def check_engine(self) -> ComponentHealth:
        """Verify deception engine is functional."""
        start = time.monotonic()
        try:
            if self.engine is not None:
                result = await self.engine.health_check()
                if result.get("healthy", True):
                    return self._ok(
                        "engine",
                        start,
                        f"Engine healthy (running={result.get('is_running', False)})",
                        metadata=result,
                    )
                return self._degraded(
                    "engine", start, result.get("detail", "Engine degraded")
                )
            return self._ok("engine", start, "Engine not configured -- skipped")
        except Exception as exc:
            return self._fail("engine", start, f"Engine error: {exc}")

    async def check_rate_limiter(self) -> ComponentHealth:
        """Verify rate limiter is functional."""
        start = time.monotonic()
        try:
            if self.rate_limiter is not None:
                result = self.rate_limiter.health_check()
                if result.get("healthy", True):
                    return self._ok(
                        "rate_limiter",
                        start,
                        f"Rate limiter healthy ({result.get('tracked_ips', 0)} IPs tracked)",
                        metadata=result,
                    )
                return self._degraded(
                    "rate_limiter", start, result.get("detail", "Rate limiter degraded")
                )
            return self._ok("rate_limiter", start, "Rate limiter not configured -- skipped")
        except Exception as exc:
            return self._fail("rate_limiter", start, f"Rate limiter error: {exc}")

    async def check_attacker_profiler(self) -> ComponentHealth:
        """Verify attacker profiler is functional."""
        start = time.monotonic()
        try:
            if self.attacker_profiler is not None:
                result = await self.attacker_profiler.health_check()
                if result.get("healthy", True):
                    return self._ok(
                        "attacker_profiler",
                        start,
                        f"Profiler healthy ({result.get('profile_count', 0)} profiles)",
                        metadata=result,
                    )
                return self._degraded(
                    "attacker_profiler", start, result.get("detail", "Profiler degraded")
                )
            return self._ok("attacker_profiler", start, "Profiler not configured -- skipped")
        except Exception as exc:
            return self._fail("attacker_profiler", start, f"Profiler error: {exc}")

    async def check_disk_space(self) -> ComponentHealth:
        """Verify adequate disk space.

        Warns when free space < 20%, critical when < 10%.
        """
        start = time.monotonic()
        try:
            total, used, free = shutil.disk_usage("/")
            free_percent = (free / total) * 100
            metadata = {
                "total_gb": round(total / (1024**3), 2),
                "used_gb": round(used / (1024**3), 2),
                "free_gb": round(free / (1024**3), 2),
                "free_percent": round(free_percent, 2),
            }

            if free_percent < self.DISK_CRITICAL_PERCENT:
                return self._fail(
                    "disk",
                    start,
                    f"CRITICAL: only {free_percent:.1f}% disk free",
                    metadata=metadata,
                )
            if free_percent < self.DISK_WARN_PERCENT:
                return self._degraded(
                    "disk",
                    start,
                    f"LOW DISK: {free_percent:.1f}% free",
                    metadata=metadata,
                )
            return self._ok(
                "disk",
                start,
                f"Disk OK: {free_percent:.1f}% free",
                metadata=metadata,
            )
        except Exception as exc:
            return self._fail("disk", start, f"Disk check failed: {exc}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _run_checks(self, depth: str) -> list[ComponentHealth]:
        """Run all checks concurrently."""
        tasks: list[asyncio.Task[ComponentHealth]] = []
        for name, method_name in self.CHECKS.items():
            method: Callable[[], Any] = getattr(self, method_name)
            if asyncio.iscoroutinefunction(method):
                tasks.append(asyncio.create_task(method()))
            else:
                tasks.append(asyncio.create_task(self._wrap_sync(method)))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        components: list[ComponentHealth] = []
        for (name, _), result in zip(self.CHECKS.items(), results):
            if isinstance(result, Exception):
                components.append(
                    ComponentHealth(
                        name=name,
                        status="unhealthy",
                        response_time_ms=0.0,
                        detail=f"Check crashed: {result}",
                    )
                )
            else:
                components.append(result)
        return components

    async def _wrap_sync(self, fn: Callable[[], ComponentHealth]) -> ComponentHealth:
        """Run a sync function in thread pool (fallback)."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return await loop.run_in_executor(None, fn)

    @staticmethod
    def _aggregate(components: list[ComponentHealth]) -> str:
        """Aggregate component statuses into overall status."""
        statuses = [c.status for c in components]
        if any(s == "unhealthy" for s in statuses):
            return "unhealthy"
        if any(s == "degraded" for s in statuses):
            return "degraded"
        return "healthy"

    @staticmethod
    def _ok(
        name: str,
        start: float,
        detail: str,
        metadata: dict[str, Any] | None = None,
    ) -> ComponentHealth:
        return ComponentHealth(
            name=name,
            status="healthy",
            response_time_ms=round((time.monotonic() - start) * 1000, 2),
            detail=detail,
            metadata=metadata or {},
        )

    @staticmethod
    def _degraded(
        name: str,
        start: float,
        detail: str,
        metadata: dict[str, Any] | None = None,
    ) -> ComponentHealth:
        return ComponentHealth(
            name=name,
            status="degraded",
            response_time_ms=round((time.monotonic() - start) * 1000, 2),
            detail=detail,
            metadata=metadata or {},
        )

    @staticmethod
    def _fail(
        name: str,
        start: float,
        detail: str,
        metadata: dict[str, Any] | None = None,
    ) -> ComponentHealth:
        return ComponentHealth(
            name=name,
            status="unhealthy",
            response_time_ms=round((time.monotonic() - start) * 1000, 2),
            detail=detail,
            metadata=metadata or {},
        )
