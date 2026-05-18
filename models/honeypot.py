"""
Honeypot instance and related models.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class HoneypotType(str, Enum):
    SSH = "ssh"
    HTTP = "http"
    FTP = "ftp"
    DATABASE = "database"


class InstanceStatus(str, Enum):
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    COMPROMISED = "compromised"
    DESTROYING = "destroying"
    DESTROYED = "destroyed"


class InstanceMetrics(BaseModel):
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    network_rx_bytes: int = 0
    network_tx_bytes: int = 0
    interaction_count: int = 0


class DecoyPersona(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    role: str = "developer"
    name: str = ""
    username: str = ""
    password_hint: str = ""
    ssh_keys: list[str] = Field(default_factory=list)
    file_preferences: list[str] = Field(default_factory=list)
    typical_commands: list[str] = Field(default_factory=list)
    environment_vars: dict[str, str] = Field(default_factory=dict)
    fake_projects: list[str] = Field(default_factory=list)


class TTPRecord(BaseModel):
    """Unified MITRE ATT&CK technique observation.

    Merges fields from all TTPRecord variants across the codebase so
    every consumer can use direct attribute access — no getattr fallbacks.
    """

    technique_id: str = ""
    name: str = ""              # technique name (from ttp_extractor / threat_scorer)
    technique: str = ""         # alias for name (from attacker_profiler)
    description: str = ""       # observed procedure (from ttp_extractor / threat_scorer)
    procedure: str = ""         # alias for description (from attacker_profiler)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    sources: list[str] = Field(default_factory=list)   # source interaction IDs
    evidence: list[str] = Field(default_factory=list)  # alias for sources (from attacker_profiler)
    tactic: str = ""
    tactic_id: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class ThreatScore(BaseModel):
    """Unified composite threat assessment (floats 0-1)."""

    profile_id: UUID | None = None
    overall: float = Field(default=0.0, ge=0.0, le=1.0)
    sophistication: float = Field(default=0.0, ge=0.0, le=1.0)
    persistence: float = Field(default=0.0, ge=0.0, le=1.0)
    stealth: float = Field(default=0.0, ge=0.0, le=1.0)
    aggressiveness: float = Field(default=0.0, ge=0.0, le=1.0)
    adaptability: float = Field(default=0.0, ge=0.0, le=1.0)
    rationale: list[str] = Field(default_factory=list)


class HoneypotInstance(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    type: HoneypotType = HoneypotType.SSH
    status: InstanceStatus = InstanceStatus.PROVISIONING
    persona: DecoyPersona | None = None
    network_zone: str = ""
    exposed_ports: list[int] = Field(default_factory=list)
    container_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    metrics: InstanceMetrics = Field(default_factory=InstanceMetrics)
