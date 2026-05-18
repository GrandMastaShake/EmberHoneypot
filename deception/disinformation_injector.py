"""Disinformation Injector -- Poisons attacker reconnaissance data."""

from __future__ import annotations

import hashlib
import hmac
import os
import random
import string
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field




class Tripwire(BaseModel):
    """A tripwire file to detect unauthorized access."""
    path: str
    bait_type: str
    triggered: bool = False
    trigger_timestamp: datetime | None = None
    honeypot_id: str = ""
    content_preview: str = ""
    expected_access_pattern: str = ""


class HoneyToken(BaseModel):
    """A fake credential that triggers alerts when used."""
    token_type: str
    value: str
    description: str = ""
    embed_in: list[str] = Field(default_factory=list)


class DisinformationInjector:
    """Inject disinformation and tracking mechanisms."""

    _HOSTS = [
        "10.0.10.10    git.acme.corp", "10.0.10.11    ci-jenkins.acme.corp",
        "10.0.20.10    api-gateway.internal", "10.0.20.11    app-server-01.internal",
        "10.0.30.10    db-primary.internal", "10.0.30.11    db-replica-01.internal",
        "10.0.30.20    cache-redis-01.internal", "10.0.40.10    monitor-prometheus.internal",
        "10.0.40.20    bastion-01.internal", "10.0.50.10    dev-workstation-01.internal",
    ]

    _SVCS = [
        {"port": 22, "name": "ssh"}, {"port": 80, "name": "http"}, {"port": 443, "name": "https"},
        {"port": 3306, "name": "mysql"}, {"port": 5432, "name": "postgresql"},
        {"port": 6379, "name": "redis"}, {"port": 8080, "name": "http-proxy"},
        {"port": 9200, "name": "elasticsearch"}, {"port": 27017, "name": "mongodb"},
    ]

    _TOKENS = [
        {"t": "aws_key", "d": "AWS Access Key", "g": lambda r: f"AKIA{''.join(r.choices(string.ascii_uppercase + string.digits, k=16))}"},
        {"t": "api_key", "d": "Generic API Key", "g": lambda r: f"hp_{''.join(r.choices(string.ascii_letters + string.digits, k=32))}"},
        {"t": "db_url", "d": "PostgreSQL URL", "g": lambda r: f"postgresql://dbuser:{''.join(r.choices(string.ascii_letters + string.digits, k=12))}@db-primary.internal:5432/app_db"},
        {"t": "stripe_key", "d": "Stripe Key", "g": lambda r: f"sk_live_{''.join(r.choices(string.ascii_letters + string.digits, k=24))}"},
        {"t": "github_token", "d": "GitHub PAT", "g": lambda r: f"ghp_{''.join(r.choices(string.ascii_letters + string.digits, k=36))}"},
        {"t": "slack_webhook", "d": "Slack Webhook", "g": lambda r: f"https://hooks.slack.com/services/{''.join(r.choices(string.ascii_letters + string.digits, k=9))}/{''.join(r.choices(string.ascii_letters + string.digits, k=12))}/{''.join(r.choices(string.ascii_letters + string.digits, k=24))}"},
        {"t": "password", "d": "App Password", "g": lambda r: f"{r.choice(string.ascii_letters).upper()}{''.join(r.choices(string.ascii_letters + string.digits + '!@#$%^&*', k=11))}"},
    ]

    def __init__(self, seed: int | None = None) -> None:
        self._rnd = random.Random(seed)

    def poison_recon_data(self, attacker_ip: str) -> dict[str, Any]:
        visible = self._rnd.sample(self._HOSTS, self._rnd.randint(5, len(self._HOSTS)))
        hosts = "\n".join(["127.0.0.1       localhost", "127.0.1.1       web-prod-01.acme.corp", "", "# Internal hosts"] + visible)
        svcs = self._rnd.sample(self._SVCS, self._rnd.randint(4, 8))
        routes = "Kernel IP routing table\n" + "\n".join([
            "Destination     Gateway         Genmask         Flags",
            "0.0.0.0         10.0.10.1       0.0.0.0         UG",
            "10.0.10.0       0.0.0.0         255.255.255.0   U",
            "10.0.20.0       10.0.20.1       255.255.255.0   UG",
            "10.0.30.0       10.0.30.1       255.255.255.0   UG",
        ])
        netstat = ["Active Internet connections", "Proto Recv-Q Send-Q Local Address    State"]
        for s in svcs:
            netstat.append(f"tcp   0      0      0.0.0.0:{s['port']}       LISTEN")
        return {
            "hosts_file": hosts, "services": svcs, "routes": routes,
            "netstat": "\n".join(netstat),
            "subnets": [
                {"name": "DMZ", "cidr": "10.0.10.0/24", "gateway": "10.0.10.1"},
                {"name": "APP", "cidr": "10.0.20.0/24", "gateway": "10.0.20.1"},
                {"name": "DB", "cidr": "10.0.30.0/24", "gateway": "10.0.30.1"},
            ],
            "domain": "acme.corp", "_attacker_ip": attacker_ip,
            "_generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def watermark_payload(self, payload: str, honeypot_id: str) -> str:
        sig = hmac.new(b"emberhoneypot-secret", f"{honeypot_id}:{int(time.time())}".encode(), hashlib.sha256).hexdigest()[:16]
        zw = {"0": "\u200B", "1": "\u200C", "2": "\u200D", "3": "\u2060", "4": "\uFEFF",
              "5": "\u200B\u200C", "6": "\u200B\u200D", "7": "\u200B\u2060", "8": "\u200B\uFEFF",
              "9": "\u200C\u200B", "a": "\u200C\u200D", "b": "\u200C\u2060", "c": "\u200C\uFEFF",
              "d": "\u200D\u200B", "e": "\u200D\u200C", "f": "\u200D\u2060"}
        wm = "".join(zw.get(c, "") for c in sig)
        if payload and "\n" in payload:
            lines = payload.split("\n")
            pos = self._rnd.randint(1, max(1, len(lines) - 1))
            lines.insert(pos, wm)
            return "\n".join(lines)
        return payload + wm

    def extract_watermark(self, payload: str) -> str | None:
        zs = {"\u200B", "\u200C", "\u200D", "\u2060", "\uFEFF"}
        ex = [c for c in payload if c in zs]
        if not ex:
            return None
        rev = {"\u200B": "0", "\u200C": "1", "\u200D": "2", "\u2060": "3", "\uFEFF": "4",
               "\u200B\u200C": "5", "\u200B\u200D": "6", "\u200B\u2060": "7", "\u200B\uFEFF": "8",
               "\u200C\u200B": "9", "\u200C\u200D": "a", "\u200C\u2060": "b", "\u200C\uFEFF": "c",
               "\u200D\u200B": "d", "\u200D\u200C": "e", "\u200D\u2060": "f"}
        res, i = "", 0
        while i < len(ex):
            d = ex[i] + (ex[i + 1] if i + 1 < len(ex) else "")
            if d in rev and len(d) == 2:
                res += rev[d]
                i += 2
                continue
            res += rev.get(ex[i], "?")
            i += 1
        return res if len(res) == 16 and all(c in "0123456789abcdef" for c in res) else None

    def generate_honey_tokens(self, count: int) -> list[HoneyToken]:
        out, used = [], set()
        for _ in range(count):
            t = self._rnd.choice(self._TOKENS)
            if t["t"] in used:
                continue
            used.add(t["t"])
            tid = str(uuid.uuid4())[:8]
            out.append(HoneyToken(token_type=t["t"], value=t["g"](self._rnd),
                                  description=f"{t['d']} [token:{tid}]",
                                  embed_in=self._suggest(t["t"])))
        return out

    def create_tripwires(self, paths: list[str] | None = None) -> list[Tripwire]:
        paths = paths or ["/opt/secrets", "/backup", "/var/www"]
        baits = [
            {"type": "credential_file", "file": "credentials.ini", "preview": "[db]\nhost=db-primary\npassword=***"},
            {"type": "config_file", "file": "config.yml", "preview": "database_url: postgresql://admin:***@db/app_db"},
            {"type": "ssh_key", "file": "id_rsa.bak", "preview": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA..."},
            {"type": "database_dump", "file": "backup.sql", "preview": "INSERT INTO users ..."},
            {"type": "env_file", "file": ".env", "preview": "DATABASE_URL=...\nSECRET_KEY=..."},
        ]
        out = []
        for path in paths:
            for _ in range(self._rnd.randint(1, 2)):
                b = self._rnd.choice(baits)
                out.append(Tripwire(path=f"{path}/{b['file']}", bait_type=b["type"],
                                    triggered=False, content_preview=b["preview"]))
        return out

    def mark_triggered(self, tripwire: Tripwire, honeypot_id: str = "") -> Tripwire:
        tripwire.triggered = True
        tripwire.trigger_timestamp = datetime.now(timezone.utc)
        if honeypot_id:
            tripwire.honeypot_id = honeypot_id
        return tripwire

    def _suggest(self, tt: str) -> list[str]:
        locs = {"aws_key": ["~/.aws/credentials", "/opt/app/.env"],
                "api_key": ["~/.bashrc", "/opt/app/.env"],
                "db_url": ["~/.bashrc", "/opt/app/.env"],
                "stripe_key": ["/opt/app/.env"],
                "github_token": ["~/.git-credentials"],
                "slack_webhook": ["/opt/app/.env"],
                "password": ["/opt/app/.env", "~/.my.cnf"]}
        return locs.get(tt, ["/opt/app/.env"])
