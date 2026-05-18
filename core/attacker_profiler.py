"""
Attacker Profiler — builds persistent fingerprints from interaction history.

Track 2a: EmberHoneypot Core + API Layer
"""

from __future__ import annotations

import json
import logging
import math
import re
from collections import Counter
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from ember_honeypot.models import TTPRecord
from ember_honeypot.core.interaction_logger import InteractionLog, InteractionLogger, InteractionType

logger = logging.getLogger(__name__)


# ── Sophistication Level ─────────────────────────────────────────────────


class SophisticationLevel(str, Enum):
    """Attacker sophistication classification."""

    SCRIPT_KIDDIE = "script_kiddie"
    AUTOMATED = "automated"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    APT = "apt"


# ── TTP Patterns ─────────────────────────────────────────────────────────


# Known tool signatures extracted from commands/payloads
_TOOL_SIGNATURES: dict[str, list[str]] = {
    "nmap": ["nmap", "-sS", "-sV", "-O", "-A", "--script"],
    "sqlmap": ["sqlmap", "--dump", "--tables", "--dbs", "--batch"],
    "metasploit": ["msfconsole", "msfvenom", "exploit", "meterpreter", "reverse_tcp"],
    "hydra": ["hydra", "-l", "-P", "-t", "ssh://", "ftp://"],
    "gobuster": ["gobuster", "dir", "-w", "-u", "-x"],
    "nikto": ["nikto", "-h", "-Cgidirs"],
    "dirb": ["dirb", "-o", "-X", "-r"],
    "curl": ["curl", "-X", "--data", "-H", "--user-agent"],
    "wget": ["wget", "--no-check-certificate", "-O", "-P"],
    "nc": ["nc", "netcat", "-e", "/bin/sh", "-lvnp"],
    "python": ["python", "python3", "-c", "__import__", "socket", "subprocess"],
    "perl": ["perl", "-e", "system", "exec"],
    "bash": ["bash", "/dev/tcp/", "exec", "<>"],
    "ssh": ["ssh", "-i", "-p", "-o", "StrictHostKeyChecking"],
    "ftp": ["ftp", "get", "put", "binary", "ascii"],
}

# MITRE ATT&CK technique mapping from observed commands
_TECHNIQUE_MAP: dict[str, tuple[str, str, str]] = {
    # Reconnaissance
    "nmap": ("Reconnaissance", "TA0043", "Active Scanning"),
    "whois": ("Reconnaissance", "TA0043", "Gather Victim Network Information"),
    "dig": ("Reconnaissance", "TA0043", "Gather Victim Network Information"),
    "nslookup": ("Reconnaissance", "TA0043", "Gather Victim Network Information"),
    # Initial Access
    "ssh": ("Initial Access", "TA0001", "Exploit Public-Facing Application"),
    "brute": ("Initial Access", "TA0001", "Brute Force"),
    "hydra": ("Initial Access", "TA0001", "Brute Force"),
    # Execution
    "python": ("Execution", "TA0002", "Command and Scripting Interpreter"),
    "perl": ("Execution", "TA0002", "Command and Scripting Interpreter"),
    "bash": ("Execution", "TA0002", "Unix Shell"),
    "sh": ("Execution", "TA0002", "Unix Shell"),
    # Persistence
    "crontab": ("Persistence", "TA0003", "Scheduled Task/Job"),
    "cron": ("Persistence", "TA0003", "Scheduled Task/Job"),
    "systemctl": ("Persistence", "TA0003", "Create or Modify System Process"),
    "rc.local": ("Persistence", "TA0003", "Boot or Logon Initialization Scripts"),
    # Privilege Escalation
    "sudo": ("Privilege Escalation", "TA0004", "Abuse Elevation Control Mechanism"),
    "su": ("Privilege Escalation", "TA0004", "Valid Accounts"),
    "chmod": ("Privilege Escalation", "TA0004", "File and Directory Permissions Modification"),
    "chown": ("Privilege Escalation", "TA0004", "File and Directory Permissions Modification"),
    # Defense Evasion
    "base64": ("Defense Evasion", "TA0005", "Obfuscated Files or Information"),
    "openssl": ("Defense Evasion", "TA0005", "Obfuscated Files or Information"),
    "rm": ("Defense Evasion", "TA0005", "Indicator Removal"),
    "history": ("Defense Evasion", "TA0005", "Clear Command History"),
    # Credential Access
    "cat /etc/shadow": ("Credential Access", "TA0006", "OS Credential Dumping"),
    "cat /etc/passwd": ("Credential Access", "TA0006", "OS Credential Dumping"),
    "mimikatz": ("Credential Access", "TA0006", "OS Credential Dumping"),
    "hashdump": ("Credential Access", "TA0006", "OS Credential Dumping"),
    # Discovery
    "ls": ("Discovery", "TA0007", "File and Directory Discovery"),
    "find": ("Discovery", "TA0007", "File and Directory Discovery"),
    "ps": ("Discovery", "TA0007", "Process Discovery"),
    "netstat": ("Discovery", "TA0007", "Network Service Discovery"),
    "ss": ("Discovery", "TA0007", "Network Service Discovery"),
    "ifconfig": ("Discovery", "TA0007", "System Network Configuration Discovery"),
    "ip addr": ("Discovery", "TA0007", "System Network Configuration Discovery"),
    "uname": ("Discovery", "TA0007", "System Information Discovery"),
    "cat /etc/os-release": ("Discovery", "TA0007", "System Information Discovery"),
    "df": ("Discovery", "TA0007", "System Network Configuration Discovery"),
    "free": ("Discovery", "TA0007", "System Information Discovery"),
    # Lateral Movement
    "scp": ("Lateral Movement", "TA0008", "Remote Services"),
    "rsync": ("Lateral Movement", "TA0008", "Remote Services"),
    # Collection
    "tar": ("Collection", "TA0009", "Archive Collected Data"),
    "zip": ("Collection", "TA0009", "Archive Collected Data"),
    "scp": ("Collection", "TA0009", "Data from Local System"),
    # Command and Control
    "nc": ("Command and Control", "TA0011", "Application Layer Protocol"),
    "curl": ("Command and Control", "TA0011", "Application Layer Protocol"),
    "wget": ("Command and Control", "TA0011", "Application Layer Protocol"),
    # Exfiltration
    "curl.*-X POST": ("Exfiltration", "TA0010", "Exfiltration Over Web Service"),
}

# ── Pydantic Models ──────────────────────────────────────────────────────


class ToolDetection(BaseModel):
    """A detected tool used by the attacker."""

    name: str
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AttackerProfile(BaseModel):
    """Persistent fingerprint of an attacker built from observed behavior."""

    # Identity
    ip: str = ""
    id: str = ""
    source_ips: list[str] = Field(default_factory=list)

    # Timing
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Statistics
    interaction_count: int = 0
    total_commands: int = 0
    unique_commands: int = 0
    session_count: int = 0

    # Classification
    sophistication: float = 0.0  # 0.0 to 1.0
    sophistication_level: SophisticationLevel = SophisticationLevel.SCRIPT_KIDDIE
    threat_score: int = 0  # 0-100 composite

    # TTPs and tools
    ttp_list: list[TTPRecord] = Field(default_factory=list)
    tools_detected: list[ToolDetection] = Field(default_factory=list)
    intents: list[str] = Field(default_factory=list)

    # Command analysis
    command_histogram: dict[str, int] = Field(default_factory=dict)
    favorite_commands: list[str] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}


# ── AttackerProfiler ─────────────────────────────────────────────────────


class AttackerProfiler:
    """Builds persistent attacker fingerprints from interaction history.

    Analyzes command patterns, detects tools, maps to MITRE ATT&CK,
    and calculates a sophistication score.
    """

    def __init__(self, interaction_logger: InteractionLogger | None = None) -> None:
        self._interaction_logger = interaction_logger
        self._profiles: dict[str, AttackerProfile] = {}
        self._ttp_db = _TECHNIQUE_MAP
        self._tool_db = _TOOL_SIGNATURES

    # ── Profiling ─────────────────────────────────────────────────────────

    async def profile_attacker(self, attacker_ip: str) -> AttackerProfile:
        """Build or refresh an attacker profile from their interaction history.

        Args:
            attacker_ip: The attacker's source IP address.

        Returns:
            Complete AttackerProfile with TTPs, tools, and scoring.
        """
        if self._interaction_logger is None:
            # Return empty profile if no logger available
            return AttackerProfile(ip=attacker_ip)

        # Fetch all interactions for this IP
        interactions = self._interaction_logger.get_interactions(
            attacker_ip=attacker_ip,
            limit=10000,
        )

        if not interactions:
            return AttackerProfile(ip=attacker_ip)

        # Build profile
        profile = AttackerProfile(
            ip=attacker_ip,
            source_ips=[attacker_ip],
            first_seen=min(i.timestamp for i in interactions),
            last_seen=max(i.timestamp for i in interactions),
            interaction_count=len(interactions),
        )

        # Extract commands
        commands: list[str] = []
        for interaction in interactions:
            payload = interaction.payload.strip()
            if interaction.interaction_type == InteractionType.COMMAND:
                commands.append(payload)
                profile.total_commands += 1
            elif interaction.interaction_type == InteractionType.HTTP_REQUEST:
                commands.append(f"[HTTP] {payload[:100]}")
                profile.total_commands += 1
            elif interaction.interaction_type == InteractionType.AUTH_ATTEMPT:
                commands.append(f"[AUTH] {payload[:50]}")

        profile.unique_commands = len(set(commands))

        # Command histogram
        profile.command_histogram = Counter(commands)
        profile.favorite_commands = [
            cmd for cmd, _ in profile.command_histogram.most_common(10)
        ]

        # Detect tools
        profile.tools_detected = self._detect_tools(interactions)

        # Extract TTPs
        profile.ttp_list = self._extract_ttps(interactions, commands)

        # Detect intents
        profile.intents = self._detect_intents(profile.ttp_list, commands)

        # Calculate sophistication
        profile.sophistication = self._calculate_sophistication(profile, interactions)
        profile.sophistication_level = self._classify_sophistication(
            profile.sophistication
        )

        # Composite threat score
        profile.threat_score = self._calculate_threat_score(profile)

        self._profiles[attacker_ip] = profile
        return profile

    def get_profile(self, attacker_ip: str) -> AttackerProfile | None:
        """Get a cached profile without rebuilding."""
        return self._profiles.get(attacker_ip)

    # ── Scoring ───────────────────────────────────────────────────────────

    async def get_sophistication_score(self, attacker_ip: str) -> float:
        """Get sophistication score for an attacker (0.0 to 1.0).

        Args:
            attacker_ip: The attacker's source IP.

        Returns:
            Sophistication score between 0.0 and 1.0.
        """
        profile = self._profiles.get(attacker_ip)
        if profile is None:
            profile = await self.profile_attacker(attacker_ip)
        return profile.sophistication

    async def get_attacker_ttp(self, attacker_ip: str) -> list[str]:
        """Get list of tactic/technique names observed for an attacker.

        Args:
            attacker_ip: The attacker's source IP.

        Returns:
            List of TTP descriptions.
        """
        profile = self._profiles.get(attacker_ip)
        if profile is None:
            profile = await self.profile_attacker(attacker_ip)
        return [
            f"[{t.tactic_id}] {t.technique}: {t.procedure[:60]}"
            for t in profile.ttp_list
        ]

    async def get_all_profiles(self) -> list[AttackerProfile]:
        """Get all cached attacker profiles."""
        return list(self._profiles.values())

    # -- Health Check --

    async def health_check(self) -> dict:
        """Return health status of the attacker profiler.

        Returns:
            Dict with keys: healthy (bool), profile_count,
            ttp_rules_loaded, tool_signatures_loaded, detail.
        """
        try:
            profile_count = len(self._profiles)
            return {
                "healthy": True,
                "name": "attacker_profiler",
                "profile_count": profile_count,
                "ttp_rules_loaded": len(self._ttp_db),
                "tool_signatures_loaded": len(self._tool_db),
                "detail": (
                    f"Tracking {profile_count} profiles, "
                    f"{len(self._ttp_db)} TTP rules, "
                    f"{len(self._tool_db)} tool signatures"
                ),
            }
        except Exception as exc:
            return {
                "healthy": False,
                "name": "attacker_profiler",
                "profile_count": 0,
                "detail": f"Profiler check failed: {exc}",
            }

    async def get_attack_timeline(
        self,
        attacker_ip: str,
    ) -> list[dict[str, Any]]:
        """Build a chronological attack timeline for visualization.

        Args:
            attacker_ip: The attacker's source IP.

        Returns:
            Ordered timeline events.
        """
        if self._interaction_logger is None:
            return []

        interactions = self._interaction_logger.get_interactions(
            attacker_ip=attacker_ip,
            limit=10000,
        )

        timeline: list[dict[str, Any]] = []
        for i, interaction in enumerate(interactions):
            event = {
                "sequence": i + 1,
                "timestamp": interaction.timestamp.isoformat(),
                "type": interaction.interaction_type.value,
                "protocol": interaction.protocol,
                "payload": interaction.payload[:200],
                "response_preview": interaction.response[:100],
                "honeypot_id": interaction.honeypot_id,
                "session_id": interaction.session_id,
            }
            timeline.append(event)

        return timeline

    # ── Internal Analysis ─────────────────────────────────────────────────

    def _detect_tools(
        self,
        interactions: list[InteractionLog],
    ) -> list[ToolDetection]:
        """Detect tools used by the attacker from interaction patterns."""
        detections: dict[str, ToolDetection] = {}

        for interaction in interactions:
            payload = interaction.payload.lower()

            for tool_name, signatures in self._tool_db.items():
                for sig in signatures:
                    if sig.lower() in payload:
                        if tool_name not in detections:
                            detections[tool_name] = ToolDetection(
                                name=tool_name,
                                evidence=[],
                            )
                        detections[tool_name].evidence.append(
                            interaction.payload[:100]
                        )
                        break

        # Calculate confidence based on evidence count
        for detection in detections.values():
            detection.confidence = min(1.0, len(detection.evidence) * 0.2 + 0.2)

        return sorted(detections.values(), key=lambda d: d.confidence, reverse=True)

    def _extract_ttps(
        self,
        interactions: list[InteractionLog],
        commands: list[str],
    ) -> list[TTPRecord]:
        """Map observed behavior to MITRE ATT&CK techniques."""
        ttp_map: dict[str, TTPRecord] = {}

        for command in commands:
            cmd_lower = command.lower()

            for pattern, (tactic, tactic_id, technique) in self._ttp_db.items():
                # Check if pattern matches
                matches = False
                if pattern.startswith("cat "):
                    matches = cmd_lower.startswith(pattern.lower())
                elif ".*" in pattern:
                    try:
                        matches = bool(re.search(pattern, cmd_lower))
                    except re.error:
                        matches = pattern.replace(".*", "") in cmd_lower
                else:
                    # Check if the command contains the pattern
                    parts = cmd_lower.split()
                    matches = pattern in parts or pattern in cmd_lower

                if matches:
                    key = f"{tactic_id}:{technique}"
                    if key not in ttp_map:
                        ttp_map[key] = TTPRecord(
                            tactic=tactic,
                            tactic_id=tactic_id,
                            technique=technique,
                            procedure=command,
                            evidence=[],
                            confidence=0.5,
                        )
                    ttp_map[key].evidence.append(command[:100])
                    ttp_map[key].confidence = min(1.0, len(ttp_map[key].evidence) * 0.15 + 0.35)
                    ttp_map[key].last_seen = datetime.now(timezone.utc)

        return list(ttp_map.values())

    def _detect_intents(
        self,
        ttps: list[TTPRecord],
        commands: list[str],
    ) -> list[str]:
        """Infer attacker intent from TTPs and commands."""
        intents: set[str] = set()
        all_cmd_lower = " ".join(commands).lower()

        # Map tactics to intents
        for ttp in ttps:
            match ttp.tactic:
                case "Reconnaissance":
                    intents.add("RECON")
                case "Initial Access":
                    intents.add("INITIAL_ACCESS")
                case "Credential Access":
                    intents.add("CREDENTIAL_ACCESS")
                case "Lateral Movement":
                    intents.add("LATERAL_MOVEMENT")
                case "Exfiltration":
                    intents.add("EXFILTRATION")
                case "Persistence":
                    intents.add("PERSISTENCE")
                case "Privilege Escalation":
                    intents.add("PRIVILEGE_ESCALATION")

        # Additional pattern-based intent detection
        if any(kw in all_cmd_lower for kw in ["wget", "curl", "download", "fetch"]):
            intents.add("PAYLOAD_DOWNLOAD")
        if any(kw in all_cmd_lower for kw in ["base64", "openssl", "enc"]):
            intents.add("EVASION")
        if any(kw in all_cmd_lower for kw in ["nc ", "ncat", "reverse", "/bin/sh"]):
            intents.add("REVERSE_SHELL")
        if any(kw in all_cmd_lower for kw in ["rm -rf", "mkfs", ":(){"]):  # fork bomb
            intents.add("DESTRUCTION")

        return sorted(intents)

    def _calculate_sophistication(
        self,
        profile: AttackerProfile,
        interactions: list[InteractionLog],
    ) -> float:
        """Calculate sophistication score (0.0 to 1.0).

        Factors:
        - Unique command diversity (more = more sophisticated)
        - Tool usage variety
        - TTP coverage (more tactics = more sophisticated)
        - Command complexity (pipes, scripting, encoding)
        - Stealth indicators (clearing history, encoded commands)
        """
        scores: list[float] = []

        # 1. Command diversity (0.0 - 0.25)
        unique_ratio = (
            profile.unique_commands / max(profile.total_commands, 1)
        )
        diversity_score = min(1.0, unique_ratio * 2) * 0.25
        scores.append(diversity_score)

        # 2. Tool variety (0.0 - 0.20)
        tool_count = len(profile.tools_detected)
        tool_score = min(1.0, tool_count / 5.0) * 0.20
        scores.append(tool_score)

        # 3. TTP coverage (0.0 - 0.25)
        unique_tactics = len(set(t.tactic for t in profile.ttp_list))
        ttp_score = min(1.0, unique_tactics / 8.0) * 0.25
        scores.append(ttp_score)

        # 4. Command complexity (0.0 - 0.20)
        complex_indicators = 0
        for cmd in profile.command_histogram:
            cmd_lower = cmd.lower()
            if "|" in cmd:  # Pipes
                complex_indicators += 1
            if ";" in cmd:  # Command chaining
                complex_indicators += 1
            if "`" in cmd or "$" in cmd:  # Command substitution
                complex_indicators += 1
            if "base64" in cmd_lower or "openssl" in cmd_lower:  # Encoding
                complex_indicators += 1
            if "python" in cmd_lower or "perl" in cmd_lower or "ruby" in cmd_lower:  # Scripting
                complex_indicators += 1

        complexity_score = min(1.0, complex_indicators / max(len(profile.command_histogram), 1) * 3) * 0.20
        scores.append(complexity_score)

        # 5. Stealth indicators (0.0 - 0.10)
        stealth_indicators = 0
        for cmd in profile.command_histogram:
            cmd_lower = cmd.lower()
            if "history" in cmd_lower:
                stealth_indicators += 1
            if "unset" in cmd_lower or "export" in cmd_lower:
                stealth_indicators += 1
            if "rm " in cmd_lower:
                stealth_indicators += 1
            if "exec" in cmd_lower:
                stealth_indicators += 1

        stealth_score = min(1.0, stealth_indicators / max(len(profile.command_histogram), 1) * 5) * 0.10
        scores.append(stealth_score)

        total = sum(scores)
        return round(min(1.0, total), 4)

    def _classify_sophistication(self, score: float) -> SophisticationLevel:
        """Map numeric score to classification level."""
        if score < 0.15:
            return SophisticationLevel.SCRIPT_KIDDIE
        if score < 0.30:
            return SophisticationLevel.AUTOMATED
        if score < 0.55:
            return SophisticationLevel.INTERMEDIATE
        if score < 0.80:
            return SophisticationLevel.ADVANCED
        return SophisticationLevel.APT

    def _calculate_threat_score(self, profile: AttackerProfile) -> int:
        """Calculate composite threat score (0-100).

        Combines sophistication, tool count, TTP diversity, and intent severity.
        """
        # Base score from sophistication
        base = profile.sophistication * 40

        # Tool multiplier
        tool_bonus = min(20, len(profile.tools_detected) * 4)

        # TTP bonus
        ttp_bonus = min(15, len(profile.ttp_list) * 3)

        # Intent severity
        severity_weights: dict[str, int] = {
            "RECON": 5,
            "INITIAL_ACCESS": 10,
            "PRIVILEGE_ESCALATION": 15,
            "PERSISTENCE": 15,
            "CREDENTIAL_ACCESS": 15,
            "LATERAL_MOVEMENT": 20,
            "EXFILTRATION": 20,
            "PAYLOAD_DOWNLOAD": 10,
            "EVASION": 15,
            "REVERSE_SHELL": 20,
            "DESTRUCTION": 25,
        }
        intent_score = sum(
            severity_weights.get(intent, 5) for intent in profile.intents
        )
        intent_bonus = min(25, intent_score)

        total = base + tool_bonus + ttp_bonus + intent_