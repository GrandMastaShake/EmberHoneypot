"""Authentication stub for the Honeypot API.

Design note: This is intentionally permissive -- we want to OBSERVE attackers,
not block them. Every request is allowed through, but we DO log authentication
attempts for intelligence gathering.

Usage::

    import os
    API_KEY = os.environ.get("SRV_API_KEY", "")
    if not API_KEY:
        raise ValueError("SRV_API_KEY must be set")
    auth = HoneypotAuth(api_key=API_KEY)
    result = auth.authenticate(request_headers)
    # result["authenticated"] is always True (honeypot never blocks)
    # result["api_key_valid"] tells us if the attacker guessed right
"""

from __future__ import annotations

import os
import time
from typing import Any

API_KEY = os.environ.get("SRV_API_KEY", "")
if not API_KEY:
    raise ValueError("SRV_API_KEY must be set")


class HoneypotAuth:
    """Authentication for the HoneyPot API.

    Note: This is intentionally permissive -- we want to observe
    attackers, not block them. But we DO track authentication
    attempts for intelligence gathering.
    """

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or API_KEY
        self._attempts: list[dict[str, Any]] = []  # Track all auth attempts

    def authenticate(self, request_headers: dict[str, str]) -> dict[str, Any]:
        """Authenticate a request. Always succeeds but logs the attempt.

        Args:
            request_headers: Dictionary of HTTP headers (key is header name).

        Returns:
            Dict with authentication result. ``authenticated`` is always True
            (we never block -- this is a honeypot).
        """
        # Accept header case-insensitively
        provided_key = ""
        for key, value in request_headers.items():
            if key.upper() == "X-API-KEY":
                provided_key = value
                break

        is_valid = provided_key == self.api_key if self.api_key is not None else None

        self._attempts.append({
            "timestamp": time.time(),
            "key_provided": bool(provided_key),
            "key_valid": is_valid,
            "key_prefix": provided_key[:8] if provided_key else None,
        })

        return {
            "authenticated": True,  # Always allow (honeypot)
            "api_key_used": bool(provided_key),
            "api_key_valid": is_valid,
        }

    def get_recent_attempts(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent authentication attempts for intelligence analysis.

        Args:
            limit: Maximum number of attempts to return (default 100, max 10,000).
        """
        limit = min(limit, 10_000)
        return self._attempts[-limit:]

    def get_attempt_stats(self) -> dict[str, Any]:
        """Return aggregate stats about auth attempts."""
        total = len(self._attempts)
        with_key = sum(1 for a in self._attempts if a["key_provided"])
        valid_key = sum(1 for a in self._attempts if a["key_valid"] is True)
        invalid_key = sum(1 for a in self._attempts if a["key_valid"] is False)
        return {
            "total_attempts": total,
            "with_api_key": with_key,
            "valid_key": valid_key,
            "invalid_key": invalid_key,
            "no_key": total - with_key,
        }

    def reset_attempts(self) -> None:
        """Clear stored attempts. Use for testing only."""
        self._attempts.clear()
