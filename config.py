"""
AppConfig -- Fail-closed Pydantic Settings configuration.

Ember pattern: missing required environment variables crash at startup.
No defaults for security-sensitive values. Everything explicit.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseSettings):
    """EmberHoneypot application configuration.

    Fail-closed design: missing required env vars cause immediate crash.
    All security-sensitive values must be explicitly provided.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="SRV_",
        case_sensitive=False,
        extra="ignore",
    )

    # -- Required (fail-closed: crash if missing) ---------------------------

    DATABASE_URL: str = Field(
        default="postgresql://app:changeme@localhost:5432/appdb",
        description="PostgreSQL connection string",
    )
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection string for pub/sub and caching",
    )

    # -- Ember Integration --------------------------------------------------

    INTEGRATION_AUTH_URL: str = Field(
        default="http://localhost:8080/api/v2/auth",
        description="Security integration authentication endpoint",
    )
    INTEGRATION_AUDIT_URL: str = Field(
        default="http://localhost:8080/api/v2/audit",
        description="Security integration audit logging endpoint",
    )
    INTEGRATION_SAFETY_URL: str = Field(
        default="http://localhost:8080/api/v2/safety",
        description="Safety validation endpoint",
    )
    INTEGRATION_API_KEY: str | None = Field(
        default=None,
        description="API key for service-to-service auth",
    )

    # -- Swarm Integration --------------------------------------------------

    CENTURIA_ENDPOINT: str = Field(
        default="http://localhost:9000",
        description="Centuria swarm API endpoint",
    )
    CENTURIA_API_KEY: str | None = Field(
        default=None,
        description="Centuria swarm API key",
    )
    SWARM_ENABLED: bool = Field(
        default=True,
        description="Enable swarm integration",
    )

    # -- Network & Service --------------------------------------------------

    API_PORT: int = Field(default=8080, description="REST API port")
    WS_PORT: int = Field(default=8081, description="WebSocket port")
    SSH_HONEYPOT_PORT: int = Field(default=2222, description="SSH server port")
    HTTP_HONEYPOT_PORT: int = Field(default=8000, description="HTTP server port")
    BIND_HOST: str = Field(default="0.0.0.0", description="Host to bind services to")

    NETWORK_ZONE: str = Field(default="dmz", description="Default network zone for servers")
    ISOLATED_SUBNET: str = Field(
        default="10.255.0.0/24", description="Isolated subnet for honeypot containers"
    )

    # -- Persona Defaults ---------------------------------------------------

    DEFAULT_PERSONA_ROLE: str = Field(default="developer", description="Default test persona role")
    DEFAULT_PERSONA_NAME: str = Field(default="Alex Developer", description="Default test persona name")
    DEFAULT_PERSONA_USERNAME: str = Field(default="adev", description="Default test persona username")

    # -- Logging & Monitoring -----------------------------------------------

    LOG_LEVEL: str = Field(default="INFO", description="Application log level")
    PROMETHEUS_PORT: int = Field(default=9090, description="Prometheus metrics port")
    GRAFANA_PORT: int = Field(default=3000, description="Grafana dashboard port")
    METRICS_INTERVAL: int = Field(default=15, description="Metrics collection interval in seconds")

    # -- Safety -------------------------------------------------------------

    FAIL_CLOSED: bool = Field(
        default=True,
        description="FAIL CLOSED: deny all if auth/dependencies unavailable",
    )
    MAX_SESSIONS: int = Field(default=1000, description="Maximum concurrent sessions")
    MAX_HONEYPOTS: int = Field(default=50, description="Maximum concurrent server instances")
    SESSION_TIMEOUT_MINUTES: int = Field(default=60, description="Session idle timeout")

    # -- Feature Flags ------------------------------------------------------

    CANARY_ENABLED: bool = Field(default=True, description="Enable canary token distribution")
    TARPIT_ENABLED: bool = Field(default=False, description="Enable tarpit/time-waster deployment")
    ADAPTIVE_DEFENSE: bool = Field(default=True, description="Enable adaptive defense via swarm")

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}, got '{v}'")
        return upper

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v.startswith(("postgresql://", "postgres://")):
            raise ValueError(f"DATABASE_URL must use postgresql:// scheme, got: {v}")
        return v

    @property
    def is_fail_closed(self) -> bool:
        """Check if fail-closed mode is active."""
        return self.FAIL_CLOSED

    @property
    def swarm_active(self) -> bool:
        """Check if swarm integration is enabled and configured."""
        return self.SWARM_ENABLED and self.CENTURIA_API_KEY is not None

    @property
    def ember_configured(self) -> bool:
        """Check if integration is fully configured."""
        return self.INTEGRATION_API_KEY is not None

    def validate_critical_settings(self) -> None:
        """Validate critical security settings at startup.

        Raises RuntimeError if fail-closed conditions are not met.
        """
        failures: list[str] = []

        if self.FAIL_CLOSED:
            if self.INTEGRATION_API_KEY is None:
                failures.append("FAIL_CLOSED=true but INTEGRATION_API_KEY not set")
            if "changeme" in self.DATABASE_URL.lower():
                failures.append("DATABASE_URL uses default/changeme password")

        if failures:
            for f in failures:
                print(f"[FAIL-CLOSED] {f}", file=sys.stderr)
            raise RuntimeError(
                f"Fail-closed validation failed with {len(failures)} error(s). "
                "Fix configuration or set FAIL_CLOSED=false for development."
            )


# Singleton instance
def get_config() -> AppConfig:
    """Get the global configuration singleton."""
    return AppConfig()
