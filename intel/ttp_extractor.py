"""TTP Extractor -- Maps observed attacker behavior to MITRE ATT&CK framework."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from ember_honeypot.models import TTPRecord


# ---------------------------------------------------------------------------
# InteractionLog stub (standalone, no external deps)
# ---------------------------------------------------------------------------

class InteractionLog(BaseModel):
    """Minimal stand-in for core.InteractionLog."""

    id: str = "stub-id"
    session_id: str = "stub-session"
    attacker_id: str = "stub-attacker"
    honeypot_id: str = "stub-honeypot"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sequence_number: int = 0
    interaction_type: str = "COMMAND"
    raw_input: str = ""
    raw_output: str = ""
    parsed_command: dict[str, Any] | None = None
    working_directory: str | None = None
    user_context: str | None = None
    environment: dict[str, str] = Field(default_factory=dict)
    source_ip: str = ""
    source_port: int = 0
    destination_port: int = 0
    protocol: str = "TCP"


# ---------------------------------------------------------------------------
# MITRE ATT&CK pattern database
# ---------------------------------------------------------------------------

_TECHNIQUE_PATTERNS: list[dict[str, Any]] = [
    {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access", "tactic_id": "TA0001",
     "patterns": [r"\bs\+\w+@", r"\bsu\s+-", r"\blogin\b", r"\bauthenticat", r"\bpasswd\b", r"\bwhoami\b"]},
    {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "tactic_id": "TA0001",
     "patterns": [r"\b(sqlmap|nmap|nikto|dirb|gobuster)", r"\bunion\s+select", r"\b\.\.\./", r"\b%2e%2e%2f"]},
    {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "tactic_id": "TA0002",
     "patterns": [r"\bbash\s+-c", r"\bsh\s+-c", r"\bpython[23]?\s+-c", r"\bcurl\s+.*\|\s*sh", r"\beval\s*\("]},
    {"technique_id": "T1053", "name": "Scheduled Task/Job", "tactic": "Execution", "tactic_id": "TA0002",
     "patterns": [r"\bcrontab\b", r"\bat\s+\d"]},
    {"technique_id": "T1543", "name": "Create or Modify System Process", "tactic": "Persistence", "tactic_id": "TA0003",
     "patterns": [r"\bsystemctl\s+enable", r"\bupdate-rc\.d", r"\bchkconfig"]},
    {"technique_id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence", "tactic_id": "TA0003",
     "patterns": [r"\b\.bashrc\b", r"\b\.profile\b", r"\b/etc/rc\.local", r"\b~/.ssh/authorized_keys"]},
    {"technique_id": "T1098", "name": "Account Manipulation", "tactic": "Persistence", "tactic_id": "TA0003",
     "patterns": [r"\buseradd\b", r"\busermod\b", r"\badduser\b"]},
    {"technique_id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "tactic_id": "TA0004",
     "patterns": [r"\bsudo\s+", r"\blinpeas", r"\blinenum", r"\bexploit"]},
    {"technique_id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion", "tactic_id": "TA0005",
     "patterns": [r"\bhistory\s+-c", r"\brm\s+-[rf].*log", r"\bunset\s+HISTFILE"]},
    {"technique_id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "tactic_id": "TA0005",
     "patterns": [r"\bbase64\b", r"\bopenssl\s+enc"]},
    {"technique_id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access", "tactic_id": "TA0006",
     "patterns": [r"\bcat\s+/etc/shadow", r"\bcat\s+/etc/passwd", r"\bmimikatz"]},
    {"technique_id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access", "tactic_id": "TA0006",
     "patterns": [r"\bcat\s+.*\.env", r"\bgrep\s+-r\s+password", r"\b\.aws/credentials"]},
    {"technique_id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery", "tactic_id": "TA0007",
     "patterns": [r"\bls\s+-[laR]+", r"\bfind\s+/"]},
    {"technique_id": "T1082", "name": "System Information Discovery", "tactic": "Discovery", "tactic_id": "TA0007",
     "patterns": [r"\buname\b", r"\bhostname\b", r"\bcat\s+/etc/os-release"]},
    {"technique_id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery", "tactic_id": "TA0007",
     "patterns": [r"\bnmap\b", r"\bping\s+-c"]},
    {"technique_id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "tactic_id": "TA0007",
     "patterns": [r"\bnmap\s+-p", r"\bnetstat\s+-[tulpan]+", r"\blsof\s+-i"]},
    {"technique_id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement", "tactic_id": "TA0008",
     "patterns": [r"\bssh\s+\d{1,3}\.", r"\bscp\s+.*\d{1,3}\.", r"\bpsql\s+-h\s+\d"]},
    {"technique_id": "T1005", "name": "Data from Local System", "tactic": "Collection", "tactic_id": "TA0009",
     "patterns": [r"\bcat\s+.*\.csv", r"\btar\s+-[czf]"]},
    {"technique_id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "tactic_id": "TA0011",
     "patterns": [r"\bcurl\s+.*http", r"\bwget\s+.*http", r"\bnc\s+.*\d{1,3}\."]},
    {"technique_id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control", "tactic_id": "TA0011",
     "patterns": [r"\bcurl\s+.*-o", r"\bwget\s+.*-O", r"\bscp\b"]},
    {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "tactic_id": "TA0010",
     "patterns": [r"\bcurl\s+.*-X\s+POST", r"\bcurl\s+.*-d\b"]},
    {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "tactic_id": "TA0040",
     "patterns": [r"\bransom", r"\bopenssl\s+enc.*-aes"]},
]


# ---------------------------------------------------------------------------
# TTPExtractor
# ---------------------------------------------------------------------------

class TTPExtractor:
    """Maps attacker behavior to MITRE ATT&CK techniques."""

    def __init__(self) -> None:
        self._compiled: list[dict[str, Any]] = []
        for tech in _TECHNIQUE_PATTERNS:
            compiled = [re.compile(p, re.IGNORECASE) for p in tech["patterns"]]
            self._compiled.append({
                "technique_id": tech["technique_id"], "name": tech["name"],
                "tactic": tech["tactic"], "tactic_id": tech["tactic_id"], "patterns": compiled,
            })

    def extract_ttp(self, interactions: list[InteractionLog]) -> list[TTPRecord]:
        """Extract TTP records from interaction logs."""
        records: dict[str, dict[str, Any]] = {}
        for interaction in interactions:
            payload = interaction.raw_input or ""
            for tech_id, tech_name, tactic, tactic_id, score in self._match_payload(payload):
                key = f"{interaction.session_id}::{tech_id}"
                if key not in records:
                    records[key] = {
                        "technique_id": tech_id, "name": tech_name, "tactic": tactic, "tactic_id": tactic_id,
                        "confidence": score, "sources": [str(interaction.id)],
                    }
                else:
                    records[key]["confidence"] = max(records[key]["confidence"], score)
                    if str(interaction.id) not in records[key]["sources"]:
                        records[key]["sources"].append(str(interaction.id))
        results: list[TTPRecord] = []
        for rec in records.values():
            results.append(TTPRecord(
                technique_id=rec["technique_id"], name=rec["name"],
                description=f"Observed {rec["technique_id"]} across {len(rec["sources"])} interaction(s)",
                confidence=round(rec["confidence"], 3), sources=rec["sources"],
                tactic=rec["tactic"], tactic_id=rec["tactic_id"],
            ))
        results.sort(key=lambda r: r.confidence, reverse=True)
        return results

    def classify_technique(self, payload: str) -> str:
        """Map payload to most likely MITRE technique name."""
        if not payload:
            return "Unknown"
        matches = self._match_payload(payload)
        return matches[0][1] if matches else "Unknown"

    def detect_lateral_movement(self, interactions: list[InteractionLog]) -> bool:
        pats = [re.compile(r) for r in [
            r"\bssh\s+\d{1,3}\.", r"\bscp\s+.*\d{1,3}\.", r"\brsync\b",
            r"\bpsql\s+-h\s+\d", r"\bmysql\s+-h\s+\d", r"\bpsexec\b",
        ]]
        return self._any_match(interactions, pats)

    def detect_persistence(self, interactions: list[InteractionLog]) -> bool:
        pats = [re.compile(r) for r in [
            r"\bcrontab\b", r"\bsystemctl\s+enable", r"\buseradd\b",
            r"\b\.ssh/authorized_keys", r"\b/etc/rc\.local",
        ]]
        return self._any_match(interactions, pats)

    def detect_reconnaissance(self, interactions: list[InteractionLog]) -> bool:
        pats = [re.compile(r) for r in [
            r"\bnmap\b", r"\bnetstat\b", r"\buname\b", r"\bifconfig\b",
            r"\bps\b.*aux", r"\blsof\b", r"\bcat\s+/etc/os-release",
        ]]
        return self._any_match(interactions, pats)

    def _match_payload(self, payload: str) -> list[tuple[str, str, str, str, float]]:
        results: list[tuple[str, str, str, str, float]] = []
        pl = payload.lower()
        for tech in self._compiled:
            mc = sum(1 for pat in tech["patterns"] if pat.search(pl))
            if mc:
                score = min(1.0, 0.4 + mc * 0.15)
                results.append((tech["technique_id"], tech["name"], tech["tactic"], tech["tactic_id"], round(score, 3)))
        return results

    def _any_match(self, interactions: list[InteractionLog], patterns: list) -> bool:
        for inter in interactions:
            pl = (inter.raw_input or "").lower()
            for pat in patterns:
                if pat.search(pl):
                    return True
        return False
