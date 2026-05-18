"""
ArmorAdapter -- Integration with SecurityPlatform v2.

Handles authentication, audit logging, safety validation, canary token
generation, and health monitoring. Stub implementation with realistic
mock responses for MVP.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SafetyResult(BaseModel):
    """Result of a safety check from Armor."""

    allowed: bool
    risk_score: int = Field(default=0, ge=0, le=100)
    reason: str = ""
    required_approvals: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None


class EmberToken(BaseModel):
    """Authentication token."""

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.issued_at + timedelta(seconds=self.expires_in)


class AuditEntry(BaseModel):
    """Single audit log entry."""

    id: UUID = Field(default_factory=uuid4)
    event_type: str
    details: dict[str, Any] = Field(default_factory=dict)
    source: str = "secure_net"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: str = "info"
    user_id: str | None = None
    session_id: str | None = None


# ---------------------------------------------------------------------------
# EmberArmorAdapter
# ---------------------------------------------------------------------------


class EmberArmorAdapter:
    """Adapter for SecurityPlatform v2 integration.

    MVP: Stub implementation with realistic mock responses.
    Phase 2: Full REST API integration with auth/audit/safety services.
    """

    def __init__(
        self,
        auth_url: str = "http://security-service:8080/api/v2/auth",
        audit_url: str = "http://security-service:8080/api/v2/audit",
        safety_url: str = "http://security-service:8080/api/v2/safety",
        canary_url: str = "http://security-service:8080/api/v2/canary",
        api_key: str | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.auth_url = auth_url
        self.audit_url = audit_url
        self.safety_url = safety_url
        self.canary_url = canary_url
        self.api_key = api_key
        self.timeout = timeout
        self._token: EmberToken | None = None
        self._auth_attempts = 0
        self._audit_log: list[AuditEntry] = []
        self._enabled = True

    # -- Authentication -------------------------------------------------------

    async def authenticate(self) -> str | None:
        """Authenticate with the security service and obtain an access token.

        Returns the access token string, or None if authentication failed.
        """
        if not self.api_key:
            logger.warning("Authentication skipped — no API key configured")
            return None

        await asyncio.sleep(0.005)  # Simulate network latency

        self._auth_attempts += 1
        token_str = self._generate_mock_token()
        self._token = EmberToken(
            access_token=token_str,
            refresh_token=secrets.token_urlsafe(32),
            expires_in=3600,
        )

        logger.info("Authenticated with security service (attempt %d)", self._auth_attempts)
        return self._token.access_token

    async def refresh_token(self) -> str | None:
        """Refresh the current access token.

        Returns the new access token, or None if refresh failed.
        """
        if not self._token:
            return await self.authenticate()

        await asyncio.sleep(0.003)
        self._token = EmberToken(
            access_token=self._generate_mock_token(),
            refresh_token=secrets.token_urlsafe(32),
            expires_in=3600,
            issued_at=datetime.now(timezone.utc),
        )
        logger.debug("Token refreshed")
        return self._token.access_token

    def get_token(self) -> str | None:
        """Get the current access token without refreshing."""
        if self._token and not self._token.is_expired:
            return self._token.access_token
        return None

    def is_authenticated(self) -> bool:
        """Check if currently authenticated with a valid token."""
        return self._token is not None and not self._token.is_expired

    # -- Audit logging --------------------------------------------------------

    async def log_audit_event(self, event_type: str, details: dict[str, Any]) -> bool:
        """Send an audit event to the audit logger.

        Returns True if the event was logged successfully.
        Failures are logged but do NOT block operations (fire-and-forget).
        """
        entry = AuditEntry(
            event_type=event_type,
            details=details,
            source="secure_net",
            severity=details.get("severity", "info"),
            user_id=details.get("user_id"),
            session_id=details.get("session_id"),
        )
        self._audit_log.append(entry)

        if not self._enabled:
            logger.warning("Audit logging disabled — event stored locally only")
            return False

        await asyncio.sleep(0.002)
        logger.debug("Audit event logged: %s", event_type)
        return True

    def get_audit_log(self, limit: int = 100) -> list[AuditEntry]:
        """Get recent audit entries (local buffer)."""
        return self._audit_log[-limit:][::-1] if limit < len(self._audit_log) else self._audit_log[::-1]

    # -- Safety validation ----------------------------------------------------

    async def check_safety(self, action: dict[str, Any]) -> SafetyResult:
        """Validate an action with the safety layer.

        Returns SafetyResult indicating whether the action is allowed,
        with risk score and any required approvals.
        """
        await asyncio.sleep(0.003)

        action_type = action.get("action_type", "unknown")
        risk_level = action.get("risk_level", "low")

        # Mock safety logic
        if risk_level == "critical":
            return SafetyResult(
                allowed=False,
                risk_score=95,
                reason=f"Critical risk action '{action_type}' requires manual approval",
                required_approvals=["security_admin", "ciso"],
            )
        elif risk_level == "high":
            return SafetyResult(
                allowed=True,
                risk_score=70,
                reason=f"High risk action '{action_type}' allowed with monitoring",
                required_approvals=["security_admin"],
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
            )
        elif risk_level == "medium":
            return SafetyResult(
                allowed=True,
                risk_score=40,
                reason=f"Medium risk action '{action_type}' approved",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
            )

        return SafetyResult(
            allowed=True,
            risk_score=10,
            reason=f"Low risk action '{action_type}' auto-approved",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )

    # -- Canary tokens --------------------------------------------------------

    async def generate_canary(self, honeypot_id: str) -> str:
        """Generate a unique canary token for a server instance.

        Returns the canary token string.
        """
        await asyncio.sleep(0.002)

        # Deterministic but unique canary per instance
        base = f"{honeypot_id}:{self.api_key or 'default'}:{time.time()}"
        token = f"SEC-CANARY-{hashlib.sha256(base.encode()).hexdigest()[:24]}"

        logger.info("Generated canary token for server %s", honeypot_id)
        return token

    # -- Health ---------------------------------------------------------------

    async def get_health(self) -> dict[str, Any]:
        """Check Armor health status.

        Returns dict with health metrics for each service.
        """
        await asyncio.sleep(0.003)

        return {
            "auth": {
                "status": "healthy" if self.is_authenticated() else "degraded",
                "endpoint": self.auth_url,
                "latency_ms": 5.2,
            },
            "audit": {
                "status": "healthy",
                "endpoint": self.audit_url,
                "queued_events": len(self._audit_log),
                "latency_ms": 2.1,
            },
            "safety": {
                "status": "healthy",
                "endpoint": self.safety_url,
                "latency_ms": 3.4,
            },
            "canary": {
                "status": "healthy",
                "endpoint": self.canary_url,
                "tokens_generated": len(self._audit_log),
                "latency_ms": 1.8,
            },
            "overall": "healthy" if self.is_authenticated() else "degraded",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # -- Circuit breaker support ----------------------------------------------

    def disable(self) -> None:
        """Disable integration (circuit breaker open)."""
        self._enabled = False
        logger.warning("Armor adapter DISABLED (circuit breaker open)")

    def enable(self) -> None:
        """Re-enable integration (circuit breaker closed)."""
        self._enabled = True
        logger.info("Armor adapter ENABLED")

    @property
    def enabled(self) -> bool:
        return self._enabled

    # -- Internal -------------------------------------------------------------

    def _generate_mock_token(self) -> str:
        """Generate a realistic mock JWT token."""
        header = secrets.token_urlsafe(32)
        payload = secrets.token_urlsafe(64)
        sig = secrets.token_urlsafe(32)
        return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." + header + "." + payload + "." + sig
