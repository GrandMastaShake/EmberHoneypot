"""
Shared data models for EmberHoneypot.
"""

from .attacker import AttackerProfile, SophisticationLevel, IntentType, ActorMatch, AttackerFingerprint
from .interaction import InteractionLog, InteractionType, ParsedCommand
from .ioc import IOC, IOCType, IOCReport
from .honeypot import (
    HoneypotInstance,
    DecoyPersona,
    TTPRecord,
    ThreatScore,
    HoneypotType,
    InstanceStatus,
    InstanceMetrics,
)

__all__ = [
    "AttackerProfile",
    "SophisticationLevel",
    "InteractionLog",
    "InteractionType",
    "ParsedCommand",
    "IOC",
    "IOCType",
    "IOCReport",
    "HoneypotInstance",
    "DecoyPersona",
    "TTPRecord",
    "ThreatScore",
    "HoneypotType",
    "InstanceStatus",
    "InstanceMetrics",
    "IntentType",
    "ActorMatch",
    "AttackerFingerprint",
]
