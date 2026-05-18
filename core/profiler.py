"""
AttackerProfiler -- Builds persistent fingerprint of each attacker.

Stub implementation for Track 2c integration testing.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from ember_honeypot.models import (
    AttackerProfile,
    InteractionLog,
    SophisticationLevel,
    IntentType,
)

logger = logging.getLogger(__name__)


class AttackerProfiler:
    """Profiles attackers based on observed behavior."""

    def __init__(self) -> None:
        self._profiles: dict[UUID, AttackerProfile] = {}
        self._ip_to_profile: dict[str, UUID] = {}

    async def fingerprint(
        self, source_ip: str, interactions: list[InteractionLog]
    ) -> AttackerProfile:
        if source_ip in self._ip_to_profile:
            profile_id = self._ip_to_profile[source_ip]
            profile = self._profiles[profile_id]
        else:
            profile_id = uuid4()
            profile = AttackerProfile(
                id=profile_id,
                source_ips=[source_ip],
            )
            self._profiles[profile_id] = profile
            self._ip_to_profile[source_ip] = profile_id

        profile.total_commands += len(interactions)
        profile.total_sessions += 1
        profile.updated_at = datetime.now(timezone.utc)

        # Classify sophistication
        profile.sophistication = self._classify_sophistication(interactions)

        # Assess intent
        profile.intent = self._assess_intent(interactions)

        # Calculate threat score
        profile.threat_score = self._calculate_threat_score(profile, interactions)

        return profile

    async def get_profile(self, profile_id: UUID) -> AttackerProfile | None:
        return self._profiles.get(profile_id)

    async def get_profile_by_ip(self, source_ip: str) -> AttackerProfile | None:
        pid = self._ip_to_profile.get(source_ip)
        if pid:
            return self._profiles.get(pid)
        return None

    async def list_profiles(self) -> list[AttackerProfile]:
        return list(self._profiles.values())

    # -- Health Check --

    async def health_check(self) -> dict:
        """Return health status of the attacker profiler.

        Returns:
            Dict with keys: healthy (bool), profile_count,
            mapped_ips, detail.
        """
        try:
            profile_count = len(self._profiles)
            mapped_ips = len(self._ip_to_profile)
            return {
                "healthy": True,
                "name": "profiler",
                "profile_count": profile_count,
                "mapped_ips": mapped_ips,
                "detail": f"Tracking {profile_count} profiles, {mapped_ips} mapped IPs",
            }
        except Exception as exc:
            return {
                "healthy": False,
                "name": "profiler",
                "profile_count": 0,
                "detail": f"Profiler check failed: {exc}",
            }

    def _classify_sophistication(
        self, interactions: list[InteractionLog]
    ) -> SophisticationLevel:
        commands = [i.raw_input for i in interactions]
        unique_cmds = len(set(commands))

        if any("nmap" in c for c in commands):
            return SophisticationLevel.INTERMEDIATE
        if any(c in ("ls", "whoami", "id") for c in commands):
            return SophisticationLevel.SCRIPT_KIDDIE
        if unique_cmds > 10:
            return SophisticationLevel.ADVANCED
        return SophisticationLevel.AUTOMATED

    def _assess_intent(self, interactions: list[InteractionLog]) -> list[IntentType]:
        commands = " ".join(i.raw_input for i in interactions).lower()
        intents: list[IntentType] = []
        if "nmap" in commands or "scan" in commands:
            intents.append(IntentType.RECON)
        if "curl" in commands or "wget" in commands:
            intents.append(IntentType.EXFILTRATION)
        if any(c in commands for c in ("ssh", "scp", "rsync")):
            intents.append(IntentType.LATERAL_MOVEMENT)
        if "crontab" in commands or "systemctl" in commands:
            intents.append(IntentType.PERSISTENCE)
        if not intents:
            intents.append(IntentType.RECON)
        return intents

    def _calculate_threat_score(
        self, profile: AttackerProfile, interactions: list[InteractionLog]
    ) -> int:
        score = min(len(interactions) * 5, 40)
        if profile.sophistication in (SophisticationLevel.ADVANCED, SophisticationLevel.APT):
            score += 30
        elif profile.sophistication == SophisticationLevel.INTERMEDIATE:
            score += 15
        if len(profile.intent) > 1:
            score += 10
        return min(score, 100)
