"""
IOC (Indicator of Compromise) models.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"
    USER_AGENT = "user_agent"
    CVE = "cve"
    YARA = "yara"


class IOC(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    session_id: UUID | None = None
    attacker_id: UUID | None = None

    ioc_type: IOCType
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    context: str = ""

    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    occurrence_count: int = 1
    associated_ttps: list[str] = Field(default_factory=list)

    stix_indicator: dict[str, Any] | None = None
    misp_attribute: dict[str, Any] | None = None


class AttackChain(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    session_id: UUID | None = None
    techniques: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    kill_chain_phases: list[str] = Field(default_factory=list)


class IOCReport(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    session_id: UUID | None = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    iocs: list[IOC] = Field(default_factory=list)
    attack_chain: AttackChain | None = None
    stix_bundle: str | None = None
    misp_event: dict[str, Any] | None = None
