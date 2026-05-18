"""
EmberHoneypot Deception Layer.
"""

from .fake_data_generator import FakeDataGenerator
from .response_engine import ResponseEngine, DecoyPersona as _DEPersona
from .disinformation_injector import DisinformationInjector, Tripwire, HoneyToken
from .decoy_persona import (
    DecoyPersona, DecoyPersonaConfig, VulnerabilityProfile,
    LegacyAPIPersona, ForgottenJenkinsPersona, LeakyS3Persona,
    ChattyDBPersona, DevServerPersona, VPNPortalPersona,
)

__all__ = [
    "FakeDataGenerator", "ResponseEngine",
    "DisinformationInjector", "Tripwire", "HoneyToken",
    "DecoyPersona", "DecoyPersonaConfig", "VulnerabilityProfile",
    "LegacyAPIPersona", "ForgottenJenkinsPersona", "LeakyS3Persona",
    "ChattyDBPersona", "DevServerPersona", "VPNPortalPersona",
]
