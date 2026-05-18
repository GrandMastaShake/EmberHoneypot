"""Rate Limiter -- In-memory request throttling per IP.

WARNING: This is intentionally a *stub* implementation for single-instance
deployments. For multi-instance / production use, replace with a Redis-backed
rate limiter.

Design note: We are a honeypot -- we want to OBSERVE attackers, not block them.
Rate limiting exists only to prevent accidental DoS (e.g. misconfigured scanners
generating billions of requests) and to keep the service stable.
"""

from __future__ import annotations

import time
from typing import Any


class RateLimitExceeded(Exception):
    """Raised when a client exceeds the configured rate limit."""

    def __init__(self, retry_after: float) -> None:
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded. Retry after {retry_after:.1f}s")


class RateLimiter:
    """Simple in-memory rate limiter.

    Tracks requests per IP address. Raises :class:`RateLimitExceeded` when limit
    is breached. Not suitable for multi-instance deployments (use Redis for that).

    Example::

        limiter = RateLimiter(max_requests=100, window_seconds=60)
        if not limiter.check("192.168.1.1"):
            raise RateLimitExceeded(limiter.window_seconds)
    """

    def __init__(self, max_requests: int = 100, window_seconds: int = 60) -> None:
        if max_requests < 1:
            raise ValueError("max_requests must be >= 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be >= 1")

        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # ip -> list of timestamp floats
        self._requests: dict[str, list[float]] = {}

    def check(self, ip: str) -> bool:
        """Check if IP is within rate limit. Returns True if allowed.

        Also increments the request counter when allowed. Call :meth:`is_allowed`
        for a non-mutating check.
        """
        now = time.time()
        timestamps = self._requests.get(ip, [])
        # Remove stale entries outside the window
        timestamps = [t for t in timestamps if now - t < self.window_seconds]
        self._requests[ip] = timestamps

        if len(timestamps) >= self.max_requests:
            return False

        timestamps.append(now)
        return True

    def is_allowed(self, ip: str) -> bool:
        """Check without incrementing counter. Returns True if IP is under limit."""
        now = time.time()
        timestamps = self._requests.get(ip, [])
        timestamps = [t for t in timestamps if now - t < self.window_seconds]
        self._requests[ip] = timestamps
        return len(timestamps) < self.max_requests

    def remaining(self, ip: str) -> int:
        """Return how many requests remain for this IP in the current window."""
        now = time.time()
        timestamps = self._requests.get(ip, [])
        timestamps = [t for t in timestamps if now - t < self.window_seconds]
        self._requests[ip] = timestamps
        return max(0, self.max_requests - len(timestamps))

    def reset(self, ip: str) -> None:
        """Reset tracking for a specific IP."""
        self._requests.pop(ip, None)

    def cleanup(self) -> int:
        """Remove stale entries for all IPs. Returns number of IPs cleaned up."""
        now = time.time()
        stale_ips = []
        for ip, timestamps in self._requests.items():
            fresh = [t for t in timestamps if now - t < self.window_seconds]
            if fresh:
                self._requests[ip] = fresh
            else:
                stale_ips.append(ip)
        for ip in stale_ips:
            del self._requests[ip]
        return len(stale_ips)

    def get_stats(self) -> dict[str, Any]:
        """Return current state for introspection / monitoring."""
        return {
            "max_requests": self.max_requests,
            "window_seconds": self.window_seconds,
            "tracked_ips": len(self._requests),
            "total_tracked_requests": sum(len(v) for v in self._requests.values()),
        }

    # -- Health Check --

    def health_check(self) -> dict:
        """Return health status of the rate limiter.

        Returns:
            Dict with keys: healthy (bool), tracked_ips,
            max_requests, window_seconds, detail.
        """
        try:
            stats = self.get_stats()
            return {
                "healthy": True,
                "name": "rate_limiter",
                "tracked_ips": stats["tracked_ips"],
                "max_requests": stats["max_requests"],
                "window_seconds": stats["window_seconds"],
                "detail": (
                    f"Tracking {stats['tracked_ips']} IPs, "
                    f"{stats['total_tracked_requests']} total requests"
                ),
            }
        except Exception as exc:
            return {
                "healthy": False,
                "name": "rate_limiter",
                "detail": f"Rate limiter check failed: {exc}",
            }
