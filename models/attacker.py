"""
Attacker profile models.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class SophisticationLevel(str, Enum):
    SCRIPT_KIDDIE = "script_kiddie"
    AUTOMATED = "automated"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    APT = "apt"


class IntentType(str, Enum):
    RECON = "recon"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    RANSOMWARE = "ransomware"
    PERSISTENCE = "persistence"


class AttackerFingerprint(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    source_ip: str
    user_agent: str | None = None
    ssh_client_version: str | None = None
    behavioral_traits: list[str] = Field(default_factory=list)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ActorMatch(BaseModel):
    actor_name: str
    confidence: float = Field(ge=0.0, le=1.0)
    matched_traits: list[str] = Field(default_factory=list)


class AuditEntry(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    action: str
    resource: str
    resource_id: UUID | None = None
    user_id: UUID | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    outcome: str = "SUCCESS"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AttackerProfile(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    source_ips: list[str] = Field(default_factory=list)
    fingerprints: list[AttackerFingerprint] = Field(default_factory=list)
    correlated_profiles: list[UUID] = Field(default_factory=list)

    sophistication: SophisticationLevel = SophisticationLevel.SCRIPT_KIDDIE
    intent: list[IntentType] = Field(default_factory=list)
    threat_score: int = Field(default=0, ge=0, le=100)

    total_sessions: int = 0
    total_commands: int = 0
    unique_commands: int = 0
    time_on_system: timedelta = Field(default_factory=lambda: timedelta(0))
    tools_observed: list[str] = Field(default_factory=list)

    matched_actors: list[ActorMatch] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    audit_log: list[AuditEntry] = Field(default_factory=list)
