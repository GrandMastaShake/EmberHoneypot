"""Fake Data Generator -- Creates realistic but fabricated data."""

from __future__ import annotations

import json
import os
import random
import string
from datetime import datetime, timedelta, timezone
from typing import Any



from pydantic import BaseModel, Field

# Maximum limits for resource-hungry generators -- prevent DoS via exhaustion
MAX_FAKE_RECORDS = 100_000  # Hard cap on database records
MAX_FAKE_FILES = 10_000     # Hard cap on generated files
MAX_FAKE_CREDENTIALS = 10_000  # Hard cap on credentials
MAX_FAKE_NETWORK_NODES = 1_000  # Hard cap on network-map nodes

_First = ["James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda",
          "David", "Elizabeth", "William", "Emma", "Olivia", "Liam", "Noah", "Ava"]
_Last = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
         "Rodriguez", "Martinez", "Hernandez", "Lopez", "Wilson", "Anderson", "Thomas"]
_Domains = ["acme.corp", "techsolutions.io", "cloudfirst.dev", "secureops.org"]
_Depts = ["Engineering", "Sales", "Marketing", "HR", "Finance", "Security", "Product"]
_Roles = ["Software Engineer", "DevOps Engineer", "Security Analyst", "Cloud Architect", "IT Manager"]
_Servers = ["web-prod-01", "api-gateway-01", "db-primary", "cache-redis-01", "ci-jenkins-01"]
_OSS = [("Ubuntu", "22.04.3 LTS", "linux"), ("CentOS", "7.9", "linux"), ("Windows Server", "2022", "windows")]
_Svcs = [("ssh", 22), ("http", 80), ("https", 443), ("mysql", 3306), ("postgresql", 5432), ("redis", 6379)]
_PW = ["Winter2024!", "Spring2024!", "Welcome1!", "Password123!", "Changeme!", "Company2024!"]


class FakeDataGenerator:
    """Generate realistic but entirely fake data for deception."""

    def __init__(self, seed: int | None = None) -> None:
        self._r = random.Random(seed)

    def _validate_bounds(self, count: int, max_val: int, name: str) -> None:
        """Validate count is within [0, max_val]. Raises ValueError if not."""
        if count < 0:
            raise ValueError(f"{name} must be non-negative, got {count}")
        if count > max_val:
            raise ValueError(f"{name} exceeds maximum of {max_val}, got {count}")

    def generate_fake_database_records(self, schema: str, count: int) -> list[dict[str, Any]]:
        self._validate_bounds(count, MAX_FAKE_RECORDS, "count")
        schema = schema.lower()
        gens = {"users": self._user, "employees": self._user, "customers": self._customer,
                "orders": self._order, "products": self._product, "transactions": self._txn,
                "credentials": self._cred}
        g = gens.get(schema, self._generic)
        out = []
        for i in range(count):
            r = g(i)
            r["_fake_id"] = i + 1
            r["_schema"] = schema
            out.append(r)
        return out

    def generate_fake_files(self, directory: str, count: int) -> list[str]:
        self._validate_bounds(count, MAX_FAKE_FILES, "count")
        safe_dir = os.path.basename(directory) if '..' in directory or '/' in directory else directory
        dp = f"/tmp/fake_data/{safe_dir}"
        types = [(".txt", self._text), (".log", self._log), (".csv", self._csv), (".json", self._json),
                 (".conf", self._conf), (".sql", self._sql), (".md", self._md), (".env", self._env),
                 (".py", self._py), (".sh", self._sh), (".yml", self._yml)]
        names = ["README", "config", "backup", "secrets", "user_list", "api_keys", "deployment", "nginx", "app", "audit"]
        out, used = [], set()
        for _ in range(count):
            ext, cg = self._r.choice(types)
            base = self._r.choice(names)
            fn = f"{base}{ext}"
            c = 1
            while fn in used:
                fn = f"{base}_{c}{ext}"
                c += 1
            used.add(fn)
            fp = dp / fn
            fp.write_text(cg(), encoding="utf-8")
            out.append(str(fp))
        return out

    def generate_fake_credentials(self, count: int) -> list[dict[str, Any]]:
        self._validate_bounds(count, MAX_FAKE_CREDENTIALS, "count")
        out, used = [], set()
        for _ in range(count):
            f = self._r.choice(_First)
            l = self._r.choice(_Last)
            d = self._r.choice(_Depts)
            u = f"{f.lower()}.{l.lower()}"
            c = 1
            while u in used:
                u = f"{f.lower()}.{l.lower()}{c}"
                c += 1
            used.add(u)
            pw = self._r.choice(_PW)
            out.append({"username": u, "password": pw, "email": f"{u}@{self._r.choice(_Domains)}",
                        "department": d, "role": self._r.choice(_Roles),
                        "mfa_enabled": self._r.choice([True, False, False, False]),
                        "account_created": self._past(1000).isoformat()})
        return out

    def generate_fake_network_map(self, node_count: int | None = None) -> dict[str, Any]:
        """Generate a fake network map.

        Args:
            node_count: Optional number of servers to generate (default: random 8-14).
                        Capped at MAX_FAKE_NETWORK_NODES.
        """
        if node_count is not None:
            self._validate_bounds(node_count, MAX_FAKE_NETWORK_NODES, "node_count")
        subnets = [{"name": "DMZ", "cidr": "10.0.10.0/24"}, {"name": "APP", "cidr": "10.0.20.0/24"},
                   {"name": "DB", "cidr": "10.0.30.0/24"}, {"name": "MGMT", "cidr": "10.0.40.0/24"}]
        servers = []
        target_count = node_count if node_count is not None else self._r.randint(8, 14)
        for _ in range(target_count):
            sn = self._r.choice(subnets)
            pre = sn["cidr"].rsplit(".", 1)[0]
            osn, osv, osf = self._r.choice(_OSS)
            svcs = [{"name": n, "port": p, "status": self._r.choice(["running", "running", "stopped"]),
                     "version": f"{self._r.randint(1,9)}.{self._r.randint(0,9)}"} for n, p in self._r.sample(_Svcs, self._r.randint(1, 3))]
            servers.append({"hostname": f"{self._r.choice(_Servers)}.{sn['name'].lower()}.local",
                            "ip": f"{pre}.{self._r.randint(2,254)}", "subnet": sn["name"],
                            "os": {"name": osn, "version": osv, "family": osf}, "services": svcs})
        return {"network_name": "ACME-CORP", "domain": "acme.corp", "subnets": subnets,
                "servers": servers, "dns_servers": ["10.0.40.10"],
                "generated_at": datetime.now(timezone.utc).isoformat()}

    # Record generators
    def _user(self, i: int) -> dict[str, Any]:
        f, l = self._r.choice(_First), self._r.choice(_Last)
        return {"employee_id": f"EMP-{self._r.randint(1000,9999):04d}", "first_name": f, "last_name": l,
                "email": f"{f.lower()}.{l.lower()}@{self._r.choice(_Domains)}",
                "department": self._r.choice(_Depts), "role": self._r.choice(_Roles),
                "salary": self._r.randint(45000, 180000), "hire_date": self._past(2000).isoformat()}

    def _customer(self, i: int) -> dict[str, Any]:
        f, l = self._r.choice(_First), self._r.choice(_Last)
        return {"customer_id": f"CUST-{self._r.randint(10000,99999):05d}", "name": f"{f} {l}",
                "email": f"{f.lower()}.{l.lower()}@{self._r.choice(_Domains)}",
                "credit_limit": self._r.randint(1000, 100000)}

    def _order(self, i: int) -> dict[str, Any]:
        return {"order_id": f"ORD-{self._r.randint(100000,999999):06d}",
                "total": round(self._r.uniform(10.0, 5000.0), 2),
                "status": self._r.choice(["pending", "processing", "delivered"]),
                "order_date": self._past(365).isoformat()}

    def _product(self, i: int) -> dict[str, Any]:
        return {"sku": f"{self._rs(3).upper()}-{self._r.randint(1000,9999)}",
                "name": f"Pro {self._rs(6)}", "price": round(self._r.uniform(9.99, 999.99), 2),
                "stock": self._r.randint(0, 10000)}

    def _txn(self, i: int) -> dict[str, Any]:
        return {"transaction_id": f"TXN-{self._r.randint(1000000,9999999):07d}",
                "amount": round(self._r.uniform(1.0, 100000.0), 2),
                "currency": self._r.choice(["USD", "EUR", "GBP"]), "timestamp": self._past(365).isoformat()}

    def _cred(self, i: int) -> dict[str, Any]:
        return {"username": f"user{self._r.randint(1,9999):04d}",
                "password_hash": f"sha256:{self._rh(64)}",
                "role": self._r.choice(["user", "admin"])}

    def _generic(self, i: int) -> dict[str, Any]:
        return {"id": i + 1, "name": f"Record {i + 1}", "created_at": self._past(365).isoformat()}

    # File content generators
    def _text(self) -> str: return f"# Report\n{self._lorem(3)}"
    def _log(self) -> str:
        return "\n".join(f"2024-01-{self._r.randint(1,30):02d} [{self._r.choice(['INFO','WARN','ERROR'])}] svc: event {i}" for i in range(20))
    def _csv(self) -> str:
        rows = ["id,name,email,dept,role"]
        for i in range(10):
            f = self._r.choice(_First)
            rows.append(f"{i},{f} {self._r.choice(_Last)},{f.lower()}@{self._r.choice(_Domains)},{self._r.choice(_Depts)},{self._r.choice(_Roles)}")
        return "\n".join(rows)
    def _json(self) -> str: return json.dumps({"app": "MyApp", "env": "prod", "key": self._rs(32)}, indent=2)
    def _conf(self) -> str: return f"[server]\nhost=0.0.0.0\nport=8080\njwt_secret={self._rs(32)}"
    def _sql(self) -> str:
        vals = ", ".join(f"('{self._r.choice(_First)}')" for _ in range(5))
        return f"CREATE TABLE users (id INT, name VARCHAR(255));\nINSERT INTO users (name) VALUES {vals};"
    def _md(self) -> str: return f"# Project\n\n{self._lorem(3)}"
    def _env(self) -> str: return f"DB_URL=postgresql://u:{self._rs(16)}@db:5432/db\nSECRET={self._rs(32)}"
    def _py(self) -> str:
        api_key = os.environ.get("SRV_FAKE_API_KEY", "")
        return f"DB_PASS = '{self._rs(16)}'\nAPI_KEY = '{api_key}'"
    def _sh(self) -> str: return f"#!/bin/bash\nDB_PASS=\"{self._rs(16)}\"\necho 'done'"
    def _yml(self) -> str: return f"apiVersion: v1\nkind: ConfigMap\ndata:\n  secret: {self._rs(16)}"

    def _lorem(self, n: int) -> str:
        w = ["lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit"]
        return " ".join(" ".join(self._r.choice(w) for _ in range(self._r.randint(6, 14))).capitalize() + "." for _ in range(n))

    def _past(self, days: int) -> datetime:
        return datetime.now(timezone.utc) - timedelta(days=self._r.randint(0, days), hours=self._r.randint(0, 23))

    def _rs(self, n: int) -> str:
        return "".join(self._r.choices(string.ascii_letters + string.digits, k=n))

    def _rh(self, n: int) -> str:
        return "".join(self._r.choices("0123456789abcdef", k=n))
