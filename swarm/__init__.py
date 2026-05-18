"""
Swarm Integration Layer

Connects EmberHoneypot to the Centuria swarm for shared intelligence,
adaptive defense coordination, and collective memory access.
"""

from .centuria_adapter import CenturiaAdapter, ThreatIntel, CollectiveMemory, IOC
from .feed_publisher import FeedPublisher
from .threat_feed import ThreatFeed, ThreatUpdate
from .adaptive_defense import AdaptiveDefense, DefenseAction
from ember_honeypot.models import ThreatScore, TTPRecord

__all__ = [
    "CenturiaAdapter",
    "ThreatIntel",
    "CollectiveMemory",
    "IOC",
    "FeedPublisher",
    "ThreatFeed",
    "ThreatUpdate",
    "AdaptiveDefense",
    "DefenseAction",
    "ThreatScore",
    "TTPRecord",
]
