"""
EmberHoneypot Intelligence Layer.
"""

from .ttp_extractor import TTPExtractor, TTPRecord, InteractionLog
from .ioc_generator import IOCGenerator, IOC, IOCType
from .threat_scorer import ThreatScorer, ThreatScore, RiskLevel
from .pattern_matcher import PatternMatcher, ActorMatch, PatternMatch, AttackerProfile

__all__ = [
    "TTPExtractor", "TTPRecord", "InteractionLog",
    "IOCGenerator", "IOC", "IOCType",
    "ThreatScorer", "ThreatScore", "RiskLevel",
    "PatternMatcher", "ActorMatch", "PatternMatch", "AttackerProfile",
]
