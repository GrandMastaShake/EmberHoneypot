"""
EmberHoneypot Core Engine — honeypot orchestration, emulation, logging, and profiling.

Track 2a: EmberHoneypot Core + API Layer
"""

from ember_honeypot.core.engine import (
    DecoyPersona,
    HoneypotConfig,
    HoneypotEngine,
    HoneypotInstance,
    HoneypotType,
    InstanceMetrics,
    InstanceStatus,
)
from ember_honeypot.core.service_emulator import (
    ConnectionContext,
    EmulatedResponse,
    HTTPEmulator,
    ProtocolType,
    SSHEmulator,
    ServiceEmulator,
)
from ember_honeypot.core.interaction_logger import (
    InteractionLog,
    InteractionLogger,
    InteractionType,
)
from ember_honeypot.core.attacker_profiler import (
    AttackerProfile,
    AttackerProfiler,
    SophisticationLevel,
    TTPRecord,
    ToolDetection,
)

__all__ = [
    # Engine
    "HoneypotEngine",
    "HoneypotConfig",
    "HoneypotInstance",
    "HoneypotType",
    "InstanceStatus",
    "InstanceMetrics",
    "DecoyPersona",
    # Service Emulator
    "ServiceEmulator",
    "SSHEmulator",
    "HTTPEmulator",
    "ConnectionContext",
    "EmulatedResponse",
    "ProtocolType",
    # Interaction Logger
    "InteractionLogger",
    "InteractionLog",
    "InteractionType",
    # Attacker Profiler
    "AttackerProfiler",
    "AttackerProfile",
    "SophisticationLevel",
    "TTPRecord",
    "ToolDetection",
]
