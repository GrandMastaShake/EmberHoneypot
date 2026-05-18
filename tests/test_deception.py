"""
test_deception.py -- Tests for the deception layer.

Covers:
- Fake data generation
- Response crafting
- Disinformation injection
- Watermarking
"""

from __future__ import annotations

import pytest
from uuid import uuid4

from ember_honeypot.deception.fake_data_generator import FakeDataGenerator
from ember_honeypot.deception.response_engine import ResponseEngine as ResponseEngineer
from ember_honeypot.deception.disinformation_injector import (
    DisinformationInjector,
    HoneyToken,
    Tripwire,
)
from ember_honeypot.models import DecoyPersona


# ---------------------------------------------------------------------------
# FakeDataGenerator
# ---------------------------------------------------------------------------

class TestFakeDataGenerator:
    """Test fake data generation."""

    def test_generate_fake_credentials(self) -> None:
        gen = FakeDataGenerator(seed=42)
        creds = gen.generate_fake_credentials(count=5)
        assert len(creds) == 5
        for c in creds:
            assert "username" in c
            assert "password" in c
            assert "email" in c
            assert "department" in c
            assert "role" in c
            assert "@" in c["email"]

    def test_generate_fake_credentials_structure(self) -> None:
        gen = FakeDataGenerator(seed=42)
        creds = gen.generate_fake_credentials(count=1)
        assert len(creds) == 1
        c = creds[0]
        assert "mfa_enabled" in c
        assert isinstance(c["mfa_enabled"], bool)
        assert "account_created" in c

    def test_generate_fake_database_records_users(self) -> None:
        gen = FakeDataGenerator(seed=42)
        records = gen.generate_fake_database_records(schema="users", count=5)
        assert len(records) == 5
        for r in records:
            assert "employee_id" in r
            assert "first_name" in r
            assert "last_name" in r
            assert "salary" in r
            assert "_schema" in r
            assert r["_schema"] == "users"

    def test_generate_fake_database_records_various_schemas(self) -> None:
        gen = FakeDataGenerator(seed=42)
        schemas = ["users", "customers", "orders", "products", "transactions", "credentials"]
        for schema in schemas:
            records = gen.generate_fake_database_records(schema=schema, count=3)
            assert len(records) == 3
            assert all(r["_schema"] == schema for r in records)

    def test_generate_fake_network_map(self) -> None:
        gen = FakeDataGenerator(seed=42)
        netmap = gen.generate_fake_network_map(node_count=5)
        assert "network_name" in netmap
        assert "domain" in netmap
        assert "servers" in netmap
        assert len(netmap["servers"]) == 5
        assert "subnets" in netmap
        assert "generated_at" in netmap
        for s in netmap["servers"]:
            assert "hostname" in s
            assert "ip" in s
            assert "services" in s
            assert "os" in s


# ---------------------------------------------------------------------------
# ResponseEngine
# ---------------------------------------------------------------------------

class TestResponseEngineer:
    """Test response crafting."""

    def test_craft_ls_response(self) -> None:
        engineer = ResponseEngineer(seed=42)
        response = engineer.craft_response("ls -la")
        assert "drwxr-xr-x" in response
        assert engineer.persona.username in response

    def test_craft_whoami_response(self) -> None:
        engineer = ResponseEngineer(seed=42)
        response = engineer.craft_response("whoami")
        assert response == engineer.persona.username

    def test_craft_unknown_command(self) -> None:
        engineer = ResponseEngineer(seed=42)
        response = engineer.craft_response("nonexistent_command_xyz")
        assert "command not found" in response

    def test_craft_http_response_root(self) -> None:
        engineer = ResponseEngineer(seed=42)
        response = engineer.craft_http_response(code=200, path="/")
        assert isinstance(response, str)
        assert "200" in response or "html" in response.lower()

    def test_craft_http_response_not_found(self) -> None:
        engineer = ResponseEngineer(seed=42)
        response = engineer.craft_http_response(code=404, path="/nonexistent")
        assert isinstance(response, str)
        assert "404" in response or "Not Found" in response

    def test_inject_errors_always_injects_at_high_rate(self) -> None:
        engineer = ResponseEngineer(seed=42)
        response = "ls -la output here"
        # With rate=0 the response should be untouched
        clean = engineer.inject_errors(response, rate=0.0)
        assert clean == response
        # With rate=1.0 an error should definitely be injected
        err = engineer.inject_errors(response, rate=1.0)
        assert err != response
        assert any(
            keyword in err
            for keyword in ("bash:", "Permission denied", "No such file", "timed out")
        )


# ---------------------------------------------------------------------------
# DisinformationInjector
# ---------------------------------------------------------------------------

class TestDisinformationInjector:
    """Test disinformation injection."""

    def test_poison_recon_data(self) -> None:
        injector = DisinformationInjector(seed=42)
        data = injector.poison_recon_data("192.168.1.100")
        assert "hosts_file" in data
        assert "services" in data
        assert "routes" in data
        assert "netstat" in data
        assert "subnets" in data
        assert "domain" in data
        assert data["domain"] == "acme.corp"
        assert isinstance(data["services"], list)
        assert len(data["services"]) >= 4
        assert "_attacker_ip" in data
        assert data["_attacker_ip"] == "192.168.1.100"

    def test_watermark_injects_invisible_mark(self) -> None:
        injector = DisinformationInjector(seed=42)
        payload = "import os\nimport sys\nprint('hello')\n"
        hid = "test-honeypot-123"
        marked = injector.watermark_payload(payload, hid)
        # Watermark ID should not appear as visible text
        assert hid not in marked
        # Original payload content should be preserved
        assert "import os" in marked
        assert "print('hello')" in marked
        # Marked payload should differ from original (watermark was inserted)
        assert marked != payload
        # The marked payload should contain zero-width characters
        zw = {"\u200B", "\u200C", "\u200D", "\u2060", "\uFEFF"}
        assert any(c in zw for c in marked)

    def test_generate_honey_tokens(self) -> None:
        injector = DisinformationInjector(seed=42)
        tokens = injector.generate_honey_tokens(count=5)
        assert isinstance(tokens, list)
        assert len(tokens) > 0
        for t in tokens:
            assert isinstance(t, HoneyToken)
            assert t.token_type != ""
            assert t.value != ""
            assert t.description != ""
