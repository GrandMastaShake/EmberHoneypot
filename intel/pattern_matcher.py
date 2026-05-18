"""Pattern Matcher -- Compares attacker behavior against known threat actor profiles."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


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


class ActorMatch(BaseModel):
    """Match against a known threat actor."""
    actor_name: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    matching_indicators: list[str] = Field(default_factory=list)
    actor_type: str = ""
    description: str = ""


class PatternMatch(BaseModel):
    """Match against a behavioral pattern."""
    pattern_name: str
    category: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    matched_indicators: list[str] = Field(default_factory=list)
    description: str = ""


class _Sig:
    def __init__(self, name: str, actor_type: str, desc: str, tools: list[str], techs: list[str], behaviors: list[str], min_c: float = 0.3) -> None:
        self.name = name
        self.actor_type = actor_type
        self.desc = desc
        self.tools = {t.lower() for t in tools}
        self.techs = set(techs)
        self.behaviors = {b.lower() for b in behaviors}
        self.min_c = min_c


_BUILTIN_SIGS: list[_Sig] = [
    _Sig("Opportunistic Scanner", "script_kiddie", "Low-skill attacker using automated scanning",
         ["nmap", "nikto", "dirb", "gobuster", "masscan", "hydra"],
         ["T1018", "T1046", "T1190"], ["port scan", "directory listing", "brute force"]),
    _Sig("Default Credential Attacker", "script_kiddie", "Attacker trying default passwords",
         ["hydra", "medusa", "ncrack"], ["T1078", "T1110"], ["password spray", "default login"]),
    _Sig("Mirai Variant", "botnet", "IoT botnet with telnet/SSH brute force",
         ["telnet", "busybox", "wget"], ["T1078", "T1105"], ["busybox", "botnet", "chmod +x"]),
    _Sig("Cryptomining Botnet", "botnet", "Botnet for cryptomining",
         ["xmrig", "minerd", "stratum"], ["T1078", "T1105"], ["xmrig", "mining pool"]),
    _Sig("Ransomware Operator", "ransomware", "Data encryption and extortion",
         ["mimikatz", "psexec", "cobalt_strike"], ["T1003", "T1021", "T1486"],
         ["encrypt", "ransom", "shadow copy delete"]),
    _Sig("State-Sponsored APT", "apt", "Sophisticated state-sponsored actor",
         ["cobalt_strike", "mimikatz", "metasploit", "bloodhound"],
         ["T1003", "T1021", "T1070", "T1078"], ["living off the land", "credential dumping"]),
    _Sig("Malicious Insider", "insider", "Authorized user abusing access",
         ["scp", "rsync", "curl", "wget"], ["T1041", "T1005"], ["bulk data access", "data export"]),
    _Sig("Disgruntled Employee", "insider", "Insider with intent to damage",
         ["rm", "dd", "mkfs", "shred"], ["T1486", "T1490", "T1499"], ["data deletion", "sabotage"]),
]

_BEHAVIORAL: list[dict[str, Any]] = [
    {"name": "Scan-and-Exploit", "category": "automated", "desc": "Quick scan then exploit",
     "tools": {"nmap", "masscan", "sqlmap"}, "behaviors": {"port scan", "exploit"}},
    {"name": "Slow-and-Stealthy", "category": "advanced", "desc": "Low-and-slow with anti-forensics",
     "tools": set(), "behaviors": {"living off the land", "anti-forensics"}},
    {"name": "Smash-and-Grab", "category": "opportunistic", "desc": "Rapid compromise and exit",
     "tools": {"wget", "curl"}, "behaviors": {"quick login", "data grab"}},
    {"name": "Credential Harvesting", "category": "credential_theft", "desc": "Focused credential theft",
     "tools": {"mimikatz", "secretsdump"}, "behaviors": {"credential dump", "pass the hash"}},
    {"name": "Lateral Movement", "category": "network_propagation", "desc": "Network spreading",
     "tools": {"psexec", "ssh"}, "behaviors": {"psexec", "network spread"}},
]


class PatternMatcher:
    """Compare attacker behavior against known threat actor profiles."""

    def __init__(self) -> None:
        self._sigs = list(_BUILTIN_SIGS)
        self._patterns = list(_BEHAVIORAL)

    def match_known_actors(self, profile: AttackerProfile) -> list[ActorMatch]:
        p_tools = {t.lower() for t in profile.tools_observed}
        p_intents = {i.lower() for i in profile.intent}
        p_techs: set[str] = set()
        for fp in profile.fingerprints:
            if isinstance(fp, dict):
                p_techs.update(fp.get("techniques", []))
                p_techs.update(fp.get("ttp_ids", []))
        p_soph = profile.sophistication.lower()
        matches: list[ActorMatch] = []
        for sig in self._sigs:
            inds: list[str] = []
            score = 0.0
            if sig.tools & p_tools:
                th = sig.tools & p_tools
                score += min(0.4, len(th) * 0.1)
                inds.extend(f"Tool:{t}" for t in th)
            if sig.techs & p_techs:
                tch = sig.techs & p_techs
                score += min(0.35, len(tch) * 0.08)
                inds.extend(f"Tech:{t}" for t in tch)
            if sig.behaviors & p_intents:
                bh = sig.behaviors & p_intents
                score += min(0.25, len(bh) * 0.08)
                inds.extend(f"Beh:{b}" for b in bh)
            sm = {"script_kiddie": ["script_kiddie"], "automated": ["automated", "script_kiddie"],
                  "intermediate": ["intermediate"], "advanced": ["advanced", "apt"], "apt": ["apt", "advanced"]}
            if sig.actor_type in sm.get(p_soph, []):
                score += 0.15
                inds.append(f"Soph:{p_soph}")
            if score >= sig.min_c:
                matches.append(ActorMatch(actor_name=sig.name, confidence=round(min(1.0, score), 3),
                                          matching_indicators=inds, actor_type=sig.actor_type, description=sig.desc))
        matches.sort(key=lambda m: m.confidence, reverse=True)
        return matches

    def match_behavioral_patterns(self, profile: AttackerProfile) -> list[PatternMatch]:
        p_tools = {t.lower() for t in profile.tools_observed}
        p_intents = {i.lower() for i in profile.intent}
        p_soph = profile.sophistication.lower()
        matches: list[PatternMatch] = []
        for pat in self._patterns:
            mi: list[str] = []
            score = 0.0
            pt = pat.get("tools", set())
            pb = pat.get("behaviors", set())
            if pt & p_tools:
                th = pt & p_tools
                score += min(0.5, len(th) * 0.12)
                mi.extend(f"T:{t}" for t in th)
            if pb & p_intents:
                bh = pb & p_intents
                score += min(0.5, len(bh) * 0.12)
                mi.extend(f"B:{b}" for b in bh)
            sb = {"Scan-and-Exploit": {"script_kiddie": 0.1, "automated": 0.15},
                  "Slow-and-Stealthy": {"advanced": 0.2, "apt": 0.25},
                  "Smash-and-Grab": {"script_kiddie": 0.1, "automated": 0.15},
                  "Credential Harvesting": {"intermediate": 0.1, "advanced": 0.15, "apt": 0.2},
                  "Lateral Movement": {"advanced": 0.2, "apt": 0.2}}
            if p_soph in sb.get(pat["name"], {}):
                score += sb[pat["name"]][p_soph]
                mi.append(f"Soph:{p_soph}")
            if pat["name"] == "Slow-and-Stealthy" and profile.time_on_system > 3600:
                score += 0.1
                mi.append("Long engagement")
            if pat["name"] == "Smash-and-Grab" and profile.total_commands < 10:
                score += 0.1
                mi.append("Few commands")
            if score >= 0.15:
                matches.append(PatternMatch(pattern_name=pat["name"], category=pat["category"],
                                            confidence=round(min(1.0, score), 3), matched_indicators=mi, description=pat["desc"]))
        matches.sort(key=lambda m: m.confidence, reverse=True)
        return matches

    def add_signature(self, sig: dict[str, Any]) -> None:
        self._sigs.append(_Sig(sig["name"], sig["actor_type"], sig.get("description", ""),
                               sig.get("tools", []), sig.get("techniques", []), sig.get("behaviors", []),
                               sig.get("min_confidence", 0.3)))

    def list_signatures(self) -> list[dict[str, Any]]:
        return [{"name": s.name, "type": s.actor_type, "tools": sorted(s.tools),
                 "techniques": sorted(s.techs), "behaviors": sorted(s.behaviors)} for s in self._sigs]
