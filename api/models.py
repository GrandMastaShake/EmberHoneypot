"""
Pydantic request/response models for the EmberHoneypot API.

Track 2a: EmberHoneypot Core + API Layer
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ── Shared Enums ─────────────────────────────────────────────────────────


class ApiHoneypotType(str, Enum):
    """API-facing server type enum."""

    SSH = "ssh"
    HTTP = "http"
    FTP = "ftp"
    DATABASE = "database"


class ApiInstanceStatus(str, Enum):
    """API-facing instance status enum."""

    PROVISIONING = "provisioning"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPROMISED = "compromised"
    DESTROYING = "destroying"
    DESTROYED = "destroyed"


class ApiInteractionType(str, Enum):
    """API-facing interaction type enum."""

    COMMAND = "command"
    QUERY = "query"
    FILE_ACCESS = "file_access"
    NETWORK = "network"
    LOGIN = "login"
    HTTP_REQUEST = "http_request"
    AUTH_ATTEMPT = os.environ.get("SRV_AUTH_ATTEMPT_TYPE", "auth_attempt")


class ApiSophisticationLevel(str, Enum):
    """API-facing sophistication level enum."""

    SCRIPT_KIDDIE = "script_kiddie"
    AUTOMATED = "automated"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    APT = "apt"


# ── Request Models ───────────────────────────────────────────────────────


class PersonaCreateRequest(BaseModel):
    """Request body for creating a new server instance."""

    role: str = "developer"
    name: str = "Alex Chen"
    username: str = "achen"
    password_hint: str = "Summer2024!"
    ssh_keys: list[str] = Field(default_factory=list)
    file_preferences: list[str] = Field(default_factory=lambda: [".py", ".sql", ".env"])
    typical_commands: list[str] = Field(
        default_factory=lambda: ["ls -la", "git status", "docker ps"]
    )
    environment_vars: dict[str, str] = Field(default_factory=lambda: {"ENV": "staging"})
    fake_projects: list[str] = Field(default_factory=lambda: ["api-gateway"])


class InteractionFilterRequest(BaseModel):
    """Query parameters for filtering interactions."""

    attacker_ip: str | None = None
    protocol: str | None = None
    honeypot_id: str | None = None
    interaction_type: ApiInteractionType | None = None
    limit: int = Field(default=100, ge=1, le=10000)
    offset: int = Field(default=0, ge=0)


class ExportRequest(BaseModel):
    """Request body for exporting logs."""

    format: str = Field(default="json", pattern="^(json|csv)$")


# ── Response Models ──────────────────────────────────────────────────────


class InstanceMetricsResponse(BaseModel):
    """Runtime metrics for a server instance."""

    interaction_count: int = 0
    attacker_count: int = 0
    command_count: int = 0
    login_attempts: int = 0
    login_successes: int = 0
    uptime_seconds: float = 0.0
    last_interaction_at: datetime | None = None


class DecoyPersonaResponse(BaseModel):
    """Decoy persona details in API responses."""

    id: str = ""
    role: str = ""
    name: str = ""
    username: str = ""
    password_hint: str = ""
    ssh_keys: list[str] = Field(default_factory=list)
    file_preferences: list[str] = Field(default_factory=list)
    typical_commands: list[str] = Field(default_factory=list)
    environment_vars: dict[str, str] = Field(default_factory=dict)
    fake_projects: list[str] = Field(default_factory=list)


class HoneypotResponse(BaseModel):
    """Single server instance response."""

    id: str = ""
    type: ApiHoneypotType = ApiHoneypotType.SSH
    status: ApiInstanceStatus = ApiInstanceStatus.PROVISIONING
    persona: DecoyPersonaResponse = Field(default_factory=DecoyPersonaResponse)
    network_zone: str = "server-net"
    exposed_ports: list[int] = Field(default_factory=list)
    container_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    banner: str = ""
    version_string: str = ""
    metrics: InstanceMetricsResponse = Field(default_factory=InstanceMetricsResponse)


class HoneypotListResponse(BaseModel):
    """Response for listing server instances."""

    instances: list[HoneypotResponse] = Field(default_factory=list)
    total: int = 0
    active_count: int = 0


class InteractionResponse(BaseModel):
    """Single interaction log entry response."""

    id: str = ""
    session_id: str = ""
    honeypot_id: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    attacker_ip: str = ""
    protocol: str = ""
    interaction_type: ApiInteractionType = ApiInteractionType.COMMAND
    payload: str = ""
    response_preview: str = ""
    parsed_command: str = ""
    user_context: str = ""


class InteractionListResponse(BaseModel):
    """Response for listing interactions."""

    interactions: list[InteractionResponse] = Field(default_factory=list)
    total: int = 0
    limit: int = 100
    offset: int = 0


class TTPResponse(BaseModel):
    """TTP record in API responses."""

    tactic: str = ""
    tactic_id: str = ""
    technique: str = ""
    technique_id: str = ""
    confidence: float = 0.0
    evidence_count: int = 0


class ToolDetectionResponse(BaseModel):
    """Tool detection in API responses."""

    name: str = ""
    confidence: float = 0.0
    evidence_count: int = 0


class AttackerProfileResponse(BaseModel):
    """Single attacker profile response."""

    ip: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    interaction_count: int = 0
    total_commands: int = 0
    unique_commands: int = 0
    sophistication: float = 0.0
    sophistication_level: ApiSophisticationLevel = ApiSophisticationLevel.SCRIPT_KIDDIE
    threat_score: int = 0
    ttp_list: list[TTPResponse] = Field(default_factory=list)
    tools_detected: list[ToolDetectionResponse] = Field(default_factory=list)
    intents: list[str] = Field(default_factory=list)
    favorite_commands: list[str] = Field(default_factory=list)


class AttackerListResponse(BaseModel):
    """Response for listing attacker profiles."""

    attackers: list[AttackerProfileResponse] = Field(default_factory=list)
    total: int = 0


class AttackTimelineEvent(BaseModel):
    """Single event in an attack timeline."""

    sequence: int = 0
    timestamp: str = ""
    type: str = ""
    protocol: str = ""
    payload: str = ""
    response_preview: str = ""
    honeypot_id: str = ""
    session_id: str = ""


class AttackTimelineResponse(BaseModel):
    """Response for an attacker's timeline."""

    attacker_ip: str = ""
    events: list[AttackTimelineEvent] = Field(default_factory=list)
    total_events: int = 0


class ComponentHealth(BaseModel):
    """Health status of a single component."""

    name: str = ""
    status: str = ""  # healthy | degraded | unhealthy
    response_time_ms: float = 0.0
    detail: str | None = None
    metadata: dict[str, Any] | None = None


class HealthResponse(BaseModel):
    """Health check response with per-component status."""

    status: str = "healthy"
    version: str = "0.1.0"
    uptime_seconds: float = 0.0
    components: list[ComponentHealth] = Field(default_factory=list)
    timestamp: str = ""


class MetricsResponse(BaseModel):
    """Prometheus metrics response."""

    metrics: str = ""


class MessageResponse(BaseModel):
    """Generic message response."""

    message: str = ""
    instance_id: str | None = None
    detail: dict[str, Any] | None = None


class ErrorResponse(BaseModel):
    """Error response model."""

    error: str = ""
    detail: str | None = None
    code: int = 500


# ── WebSocket Models ─────────────────────────────────────────────────────


class AttackEvent(BaseModel):
    """Real-time attack event pushed via WebSocket."""

    event_type: str = "interaction"  # interaction | new_attacker | ttp_detected
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attacker_ip: str = ""
    honeypot_id: str = ""
    honeypot_type: str = ""
    payload: str = ""
    interaction_type: str = ""
    protocol: str = ""
    threat_score: int = 0
    sophistication: float = 0.0
    ttp_detected: list[str] = Field(default_factory=list)

    def to_json(self) -> str:
        """Serialize to JSON string for WebSocket transmission."""
        return self.model_dump_json()


class WsAuthMessage(BaseModel):
    """WebSocket authentication message."""

    type: str = "auth"
    token: str = ""


class WsSubscribeMessage(BaseModel):
    """WebSocket subscription message."""

    type: str = "subscribe"
    channels: list[str] = Field(default_factory=lambda: ["attacks"])
