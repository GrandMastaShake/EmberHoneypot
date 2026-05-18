"""Threat Scorer -- Calculates composite threat scores."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from ember_honeypot.models import TTPRecord, ThreatScore


class AttackerProfile(BaseModel):
    """Stub for core.AttackerProfile."""
    id: str = "stub-id"
    source_ips: list[str] = Field(default_factory=list)
    fingerprints: list[dict[str, Any]] = Field(default_factory=list)
    correlated_profiles: list[str] = Field(default_factory=list)
    sophistication: str = "script_kiddie"
    intent: list[str] = Field(default_factory=list)
    threat_score: int = 0
    total_sessions: int = 0
    total_commands: int = 0
    unique_commands: int = 0
    time_on_system: float = 0.0
    tools_observed: list[str] = Field(default_factory=list)
    matched_actors: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float = 0.0


class IOC(BaseModel):
    """Stub for IOC."""
    type: str = "ip"
    value: str = ""
    confidence: float = 0.0
    context: str = ""


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatScorer:
    """Calculate composite threat scores from profiles and intelligence."""

    W_INTENT = 0.40
    W_SOPH = 0.35
    W_PERSIST = 0.25

    _SOPH_MAP = {"script_kiddie": 0.15, "automated": 0.25, "intermediate": 0.50, "advanced": 0.75, "apt": 0.95}
    _INTENT_TECHS = {"T1003", "T1005", "T1552", "T1021", "T1041", "T1048", "T1486", "T1490", "T1499", "T1543", "T1547", "T1098"}
    _PERSIST_TECHS = {"T1543", "T1547", "T1098", "T1053"}

    def __init__(self, wi: float = 0.40, ws: float = 0.35, wp: float = 0.25) -> None:
        self.W_INTENT = wi
        self.W_SOPH = ws
        self.W_PERSIST = wp
        total = wi + ws + wp
        if total > 0 and total != 1.0:
            self.W_INTENT /= total
            self.W_SOPH /= total
            self.W_PERSIST /= total

    def score_threat(self, profile: AttackerProfile, ttps: list[TTPRecord] | None = None, iocs: list[IOC] | None = None) -> ThreatScore:
        ttps = ttps or []
        iocs = iocs or []
        rat: list[str] = []
        intent = self._calc_intent(profile, ttps, iocs)
        rat.append(f"Intent: {intent:.2f}")
        soph = self._calc_soph(profile, ttps, iocs)
        rat.append(f"Sophistication: {soph:.2f}")
        persist = self._calc_persist(profile, ttps, iocs)
        rat.append(f"Persistence: {persist:.2f}")
        comp = round(intent * self.W_INTENT + soph * self.W_SOPH + persist * self.W_PERSIST, 3)
        risk = self._to_risk(comp)
        rat.append(f"Composite {comp:.2f} -> {risk.value}")
        return ThreatScore(
            overall=comp, sophistication=round(soph, 3),
            persistence=round(persist, 3), rationale=rat,
        )

    def assess_intent(self, profile: AttackerProfile, ttps: list[TTPRecord] | None = None) -> dict[str, float]:
        ttps = ttps or []
        tids = {t.technique_id for t in ttps}
        def check(techs: set[str], base: float, step: float) -> float:
            h = tids & techs
            return round(min(1.0, base + len(h) * step) if h else 0.0, 3)
        return {
            "reconnaissance": check({"T1083", "T1082", "T1018", "T1046"}, 0.3, 0.15),
            "lateral_movement": check({"T1021"}, 0.4, 0.2),
            "exfiltration": check({"T1041", "T1048", "T1560"}, 0.4, 0.2),
            "ransomware": check({"T1486", "T1490", "T1499"}, 0.5, 0.2),
            "persistence": check(self._PERSIST_TECHS, 0.4, 0.2),
            "destructive": round(min(1.0, 0.5 + len({"T1499", "T1486"} & tids) * 0.25) if ("T1499" in tids or "T1486" in tids) else 0.0, 3),
        }

    def _calc_intent(self, p: AttackerProfile, ttps: list[TTPRecord], iocs: list[IOC]) -> float:
        s = 0.0
        tids = {t.technique_id for t in ttps}
        if p.intent:
            s += min(len(p.intent) * 0.1, 0.3)
        s += min(0.6, len(tids & self._INTENT_TECHS) * 0.12)
        if "T1003" in tids or "T1552" in tids:
            s += 0.25
        if p.total_sessions > 3:
            s += min(0.15, (p.total_sessions - 3) * 0.02)
        if p.unique_commands > 20:
            s += min(0.15, (p.unique_commands - 20) * 0.005)
        return min(1.0, s)

    def _calc_soph(self, p: AttackerProfile, ttps: list[TTPRecord], iocs: list[IOC]) -> float:
        s = self._SOPH_MAP.get(p.sophistication.lower(), 0.15)
        tids = {t.technique_id for t in ttps}
        td = len(tids)
        if td > 5:
            s += min(0.2, (td - 5) * 0.02)
        tactics = {t.tactic_id for t in ttps}
        if len(tactics) > 3:
            s += min(0.15, (len(tactics) - 3) * 0.04)
        adv = {"metasploit", "cobalt_strike", "mimikatz", "empire", "bloodhound", "nmap", "sqlmap"}
        hits = {t.lower() for t in p.tools_observed} & adv
        if hits:
            s += min(0.2, len(hits) * 0.05)
        stealth = tids & {"T1070", "T1027", "T1036"}
        if stealth:
            s += min(0.15, len(stealth) * 0.05)
        if ttps:
            s += min(0.1, (sum(t.confidence for t in ttps) / len(ttps)) * 0.1)
        return min(1.0, s)

    def _calc_persist(self, p: AttackerProfile, ttps: list[TTPRecord], iocs: list[IOC]) -> float:
        s = 0.0
        tids = {t.technique_id for t in ttps}
        ph = tids & self._PERSIST_TECHS
        if ph:
            s += min(0.5, len(ph) * 0.15)
        from datetime import timedelta
        if isinstance(p.time_on_system, timedelta):
            eh = p.time_on_system.total_seconds() / 3600
        else:
            eh = p.time_on_system / 3600
        if eh > 1:
            s += min(0.2, eh * 0.02)
        if p.total_sessions > 1:
            s += min(0.15, (p.total_sessions - 1) * 0.03)
        if len(p.source_ips) > 2:
            s += min(0.1, (len(p.source_ips) - 2) * 0.02)
        if p.correlated_profiles:
            s += min(0.15, len(p.correlated_profiles) * 0.05)
        if p.matched_actors:
            s += min(0.2, len(p.matched_actors) * 0.1)
        return min(1.0, s)

    @staticmethod
    def _to_risk(c: float) -> RiskLevel:
        if c >= 0.8:
            return RiskLevel.CRITICAL
        if c >= 0.6:
            return RiskLevel.HIGH
        if c >= 0.35:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
