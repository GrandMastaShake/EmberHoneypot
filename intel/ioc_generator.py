"""IOC Generator -- Extracts Indicators of Compromise from attacker interactions."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


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


class IOCType(str, Enum):
    """Categories of IOCs."""
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"
    CVE = "cve"


class IOC(BaseModel):
    """A single Indicator of Compromise."""
    type: IOCType
    value: str
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    context: str = ""
    last_seen: datetime | None = None
    occurrence_count: int = 1

    @field_validator("confidence")
    @classmethod
    def _clamp(cls, v: float) -> float:
        return max(0.0, min(1.0, v))


class IOCGenerator:
    """Extract IOCs from honeypot interaction logs."""

    _IP_RE = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
    )
    _DOMAIN_RE = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}\b"
    )
    _URL_RE = re.compile(r"https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.~%+-]*)?)?")
    _MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
    _SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
    _SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
    _CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

    _FP_SUFFIXES = {".jpg", ".png", ".css", ".js", ".html", ".json", ".pdf", ".zip", ".sh", ".py", ".php"}
    _FP_NAMES = {"localhost", "example", "test"}

    def generate_iocs(self, interactions: list[InteractionLog]) -> list[IOC]:
        ioc_map: dict[str, IOC] = {}
        for interaction in interactions:
            payload = f"{interaction.raw_input or ''} {interaction.raw_output or ''}"
            ts = interaction.timestamp or datetime.now(timezone.utc)
            src = str(interaction.id)
            for ioc in self._extract_all(payload, src, ts):
                key = f"{ioc.type.value}:{ioc.value}"
                if key in ioc_map:
                    existing = ioc_map[key]
                    existing.occurrence_count += 1
                    existing.confidence = min(1.0, existing.confidence + 0.05)
                    if existing.last_seen is None or ioc.first_seen > existing.last_seen:
                        existing.last_seen = ioc.first_seen
                else:
                    ioc_map[key] = ioc
        results = list(ioc_map.values())
        results.sort(key=lambda i: i.confidence, reverse=True)
        return results

    def extract_ips(self, payload: str) -> list[str]:
        return [ip for ip in self._IP_RE.findall(payload) if not self._is_private(ip)]

    def extract_domains(self, payload: str) -> list[str]:
        matches = self._DOMAIN_RE.findall(payload)
        filtered: list[str] = []
        for d in matches:
            dl = d.lower()
            if any(dl.endswith(s) for s in self._FP_SUFFIXES):
                continue
            if any(fp in dl for fp in self._FP_NAMES):
                continue
            if dl.replace(".", "").isdigit():
                continue
            filtered.append(d)
        return filtered

    def extract_hashes(self, payload: str) -> list[str]:
        results: list[str] = []
        seen: set[str] = set()
        for pattern, prefix in [(self._SHA256_RE, "sha256:"), (self._SHA1_RE, "sha1:"), (self._MD5_RE, "md5:")]:
            for m in pattern.findall(payload):
                k = m.lower()
                if k not in seen:
                    seen.add(k)
                    results.append(f"{prefix}{k}")
        return results

    def extract_urls(self, payload: str) -> list[str]:
        return self._URL_RE.findall(payload)

    def extract_cves(self, payload: str) -> list[str]:
        return sorted({m.upper() for m in self._CVE_RE.findall(payload)})

    def compute_hash(self, data: bytes | str, algorithm: str = "sha256") -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        if algorithm == "md5":
            return hashlib.md5(data, usedforsecurity=False).hexdigest()
        if algorithm == "sha1":
            return hashlib.sha1(data, usedforsecurity=False).hexdigest()
        return hashlib.sha256(data).hexdigest()

    def _extract_all(self, payload: str, source: str, ts: datetime) -> list[IOC]:
        iocs: list[IOC] = []
        ctx = payload[:200]
        for ip in self.extract_ips(payload):
            iocs.append(IOC(type=IOCType.IP, value=ip, first_seen=ts, source=source, confidence=0.85, context=ctx))
        for domain in self.extract_domains(payload):
            iocs.append(IOC(type=IOCType.DOMAIN, value=domain, first_seen=ts, source=source, confidence=0.75, context=ctx))
        for h in self.extract_hashes(payload):
            iocs.append(IOC(type=IOCType.HASH, value=h, first_seen=ts, source=source, confidence=0.95, context=ctx))
        for url in self.extract_urls(payload):
            iocs.append(IOC(type=IOCType.URL, value=url, first_seen=ts, source=source, confidence=0.90, context=ctx))
        for cve in self.extract_cves(payload):
            iocs.append(IOC(type=IOCType.CVE, value=cve, first_seen=ts, source=source, confidence=0.80, context=ctx))
        return iocs

    @staticmethod
    def _is_private(ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return True
        try:
            o = [int(p) for p in parts]
        except ValueError:
            return True
        if o[0] == 127 or o[0] == 10:
            return True
        if o[0] == 172 and 16 <= o[1] <= 31:
            return True
        if o[0] == 192 and o[1] == 168:
            return True
        if o[0] == 169 and o[1] == 254:
            return True
        if o[0] in (0, 255):
            return True
        return False
