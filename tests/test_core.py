"""
test_core.py -- Tests for the core engine layer.

Covers:
- Honeypot spawn/destroy lifecycle
- SSH/HTTP emulator basic responses
- Interaction logging
- Attacker profiling
"""

from __future__ import annotations

import pytest
from uuid import UUID, uuid4

from ember_honeypot.core.orchestrator import HoneypotOrchestrator
from ember_honeypot.core.emulator import ServiceEmulator, SSHConfig, HTTPConfig
from ember_honeypot.core.logger import InteractionLogger
from ember_honeypot.core.profiler import AttackerProfiler
from ember_honeypot.models import (
    DecoyPersona,
    HoneypotType,
    InstanceStatus,
    InteractionLog,
    InteractionType,
    ParsedCommand,
    SophisticationLevel,
    IntentType,
)


# ============================================================================
# HoneypotOrchestrator Tests
# ============================================================================

class TestHoneypotOrchestrator:
    """Test honeypot lifecycle management."""

    @pytest.mark.asyncio
    async def test_create_instance(self, test_persona: DecoyPersona) -> None:
        """Test honeypot instance creation."""
        orch = HoneypotOrchestrator()
        instance = await orch.create_instance(
            service_type=HoneypotType.SSH,
            persona=test_persona,
            network_zone="dmz-01",
            duration_minutes=120,
        )
        assert instance.id is not None
        assert instance.type == HoneypotType.SSH
        assert instance.status == InstanceStatus.ACTIVE
        assert instance.persona == test_persona
        assert instance.network_zone == "dmz-01"
        assert instance.container_id is not None
        assert instance.expires_at is not None
        assert 2222 in instance.exposed_ports

    @pytest.mark.asyncio
    async def test_create_http_instance(self, test_persona: DecoyPersona) -> None:
        """Test HTTP honeypot creation."""
        orch = HoneypotOrchestrator()
        instance = await orch.create_instance(
            service_type=HoneypotType.HTTP,
            persona=test_persona,
        )
        assert instance.type == HoneypotType.HTTP
        assert 8080 in instance.exposed_ports

    @pytest.mark.asyncio
    async def test_list_instances(self, test_persona: DecoyPersona) -> None:
        """Test listing all instances."""
        orch = HoneypotOrchestrator()
        instances_before = await orch.list_instances()
        assert len(instances_before) == 0

        await orch.create_instance(HoneypotType.SSH, test_persona)
        await orch.create_instance(HoneypotType.HTTP, test_persona)

        instances = await orch.list_instances()
        assert len(instances) == 2

    @pytest.mark.asyncio
    async def test_destroy_instance(self, test_persona: DecoyPersona) -> None:
        """Test honeypot destruction."""
        orch = HoneypotOrchestrator()
        instance = await orch.create_instance(HoneypotType.SSH, test_persona)
        instance_id = instance.id

        assert len(await orch.list_instances()) == 1
        await orch.destroy_instance(instance_id)
        assert len(await orch.list_instances()) == 0

    @pytest.mark.asyncio
    async def test_get_instance(self, test_persona: DecoyPersona) -> None:
        """Test retrieving a specific instance."""
        orch = HoneypotOrchestrator()
        instance = await orch.create_instance(HoneypotType.SSH, test_persona)

        found = await orch.get_instance(instance.id)
        assert found is not None
        assert found.id == instance.id

        not_found = await orch.get_instance(uuid4())
        assert not_found is None

    @pytest.mark.asyncio
    async def test_rotate_persona(self, test_persona: DecoyPersona, admin_persona: DecoyPersona) -> None:
        """Test persona rotation on a running instance."""
        orch = HoneypotOrchestrator()
        instance = await orch.create_instance(HoneypotType.SSH, test_persona)

        assert instance.persona.role == "developer"
        await orch.rotate_persona(instance.id, admin_persona)

        updated = await orch.get_instance(instance.id)
        assert updated is not None
        assert updated.persona.role == "admin"

    @pytest.mark.asyncio
    async def test_instance_metrics(self, test_persona: DecoyPersona) -> None:
        """Test instance has metrics."""
        orch = HoneypotOrchestrator()
        instance = await orch.create_instance(HoneypotType.SSH, test_persona)
        assert instance.metrics is not None
        assert instance.metrics.cpu_percent >= 0
        assert instance.metrics.memory_mb >= 0


# ============================================================================
# ServiceEmulator Tests
# ============================================================================

class TestServiceEmulator:
    """Test service emulation."""

    @pytest.mark.asyncio
    async def test_emulate_ssh(self) -> None:
        """Test SSH emulation startup."""
        emulator = ServiceEmulator()
        config = SSHConfig(port=2222)
        result = await emulator.emulate_ssh(config)
        assert result["status"] == "running"
        assert result["port"] == 2222

    @pytest.mark.asyncio
    async def test_emulate_http(self) -> None:
        """Test HTTP emulation startup."""
        emulator = ServiceEmulator()
        config = HTTPConfig(port=8080)
        result = await emulator.emulate_http(config)
        assert result["status"] == "running"
        assert result["port"] == 8080

    @pytest.mark.asyncio
    async def test_get_banner(self) -> None:
        """Test banner retrieval."""
        emulator = ServiceEmulator()
        ssh_banner = await emulator.get_banner("ssh")
        assert "OpenSSH" in ssh_banner
        http_banner = await emulator.get_banner("http")
        assert "HTTP" in http_banner
        unknown = await emulator.get_banner("unknown")
        assert unknown == "Unknown"

    @pytest.mark.asyncio
    async def test_handle_interaction(self) -> None:
        """Test interaction handling."""
        emulator = ServiceEmulator()
        response = await emulator.handle_interaction("ssh_2222", "ls -la")
        assert "Received" in response
        assert "ls -la" in response


# ============================================================================
# InteractionLogger Tests
# ============================================================================

class TestInteractionLogger:
    """Test interaction logging."""

    @pytest.mark.asyncio
    async def test_log_command(self) -> None:
        """Test command logging."""
        logger = InteractionLogger()
        session_id = uuid4()
        attacker_id = uuid4()
        honeypot_id = uuid4()

        log = await logger.log_command(
            session_id=session_id,
            attacker_id=attacker_id,
            honeypot_id=honeypot_id,
            command="ls -la /etc",
            output="total 128...",
            metadata={"source_ip": "10.0.0.1", "source_port": 54321},
        )
        assert log.session_id == session_id
        assert log.attacker_id == attacker_id
        assert log.raw_input == "ls -la /etc"
        assert log.raw_output == "total 128..."
        assert log.source_ip == "10.0.0.1"
        assert log.sequence_number == 1
        assert log.interaction_type == InteractionType.COMMAND
        assert log.parsed_command is not None
        assert log.parsed_command.binary == "ls"

    @pytest.mark.asyncio
    async def test_log_multiple_commands_sequence(self) -> None:
        """Test sequential numbering of commands."""
        logger = InteractionLogger()
        session_id = uuid4()
        attacker_id = uuid4()
        honeypot_id = uuid4()

        for i in range(5):
            log = await logger.log_command(
                session_id=session_id,
                attacker_id=attacker_id,
                honeypot_id=honeypot_id,
                command=f"cmd{i}",
                output=f"out{i}",
            )
            assert log.sequence_number == i + 1

    @pytest.mark.asyncio
    async def test_log_login(self) -> None:
        """Test login logging."""
        logger = InteractionLogger()
        session_id = uuid4()
        attacker_id = uuid4()
        honeypot_id = uuid4()

        log = await logger.log_login(
            session_id=session_id,
            attacker_id=attacker_id,
            honeypot_id=honeypot_id,
            username="admin",
            password="password123",
            success=False,
            source_ip="10.0.0.1",
        )
        assert log.interaction_type == InteractionType.LOGIN
        assert "admin" in log.raw_input
        assert log.raw_output == "Access denied"
        assert log.source_ip == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_get_session_timeline(self) -> None:
        """Test session timeline reconstruction."""
        logger = InteractionLogger()
        session_id = uuid4()
        attacker_id = uuid4()
        honeypot_id = uuid4()

        for i in range(3):
            await logger.log_command(
                session_id=session_id,
                attacker_id=attacker_id,
                honeypot_id=honeypot_id,
                command=f"cmd{i}",
                output=f"out{i}",
            )

        timeline = await logger.get_session_timeline(session_id)
        assert len(timeline) == 3
        assert timeline[0].sequence_number == 1
        assert timeline[2].sequence_number == 3

    @pytest.mark.asyncio
    async def test_get_session_timeline_empty(self) -> None:
        """Test timeline for unknown session."""
        logger = InteractionLogger()
        timeline = await logger.get_session_timeline(uuid4())
        assert len(timeline) == 0

    @pytest.mark.asyncio
    async def test_get_all_logs(self) -> None:
        """Test retrieving all logs."""
        logger = InteractionLogger()
        session_id = uuid4()
        attacker_id = uuid4()
        honeypot_id = uuid4()

        for i in range(10):
            await logger.log_command(
                session_id=session_id,
                attacker_id=attacker_id,
                honeypot_id=honeypot_id,
                command=f"cmd{i}",
                output=f"out{i}",
            )

        all_logs = await logger.get_all_logs()
        assert len(all_logs) == 10


# ============================================================================
# AttackerProfiler Tests
# ============================================================================

class TestAttackerProfiler:
    """Test attacker profiling."""

    @pytest.mark.asyncio
    async def test_fingerprint_new_attacker(self) -> None:
        """Test creating a new attacker profile."""
        profiler = AttackerProfiler()
        interactions = [
            InteractionLog(
                id=uuid4(),
                session_id=uuid4(),
                attacker_id=uuid4(),
                honeypot_id=uuid4(),
                raw_input="nmap -sS 10.0.0.0/24",
                raw_output="Starting Nmap...",
                interaction_type=InteractionType.COMMAND,
            ),
        ]
        profile = await profiler.fingerprint("10.0.0.50", interactions)
        assert profile.source_ips == ["10.0.0.50"]
        assert profile.total_sessions == 1
        assert profile.total_commands == 1
        assert profile.threat_score > 0

    @pytest.mark.asyncio
    async def test_fingerprint_existing_attacker(self) -> None:
        """Test updating an existing attacker profile."""
        profiler = AttackerProfiler()
        interactions = [
            InteractionLog(
                id=uuid4(),
                session_id=uuid4(),
                attacker_id=uuid4(),
                honeypot_id=uuid4(),
                raw_input="ls",
                raw_output="file1 file2",
                interaction_type=InteractionType.COMMAND,
            ),
        ]
        profile1 = await profiler.fingerprint("10.0.0.50", interactions)
        first_id = profile1.id

        profile2 = await profiler.fingerprint("10.0.0.50", interactions)
        assert profile2.id == first_id  # Same attacker
        assert profile2.total_sessions == 2  # Incremented

    @pytest.mark.asyncio
    async def test_sophistication_script_kiddie(self) -> None:
        """Test classification of script kiddie."""
        profiler = AttackerProfiler()
        interactions = [
            InteractionLog(
                id=uuid4(),
                session_id=uuid4(),
                attacker_id=uuid4(),
                honeypot_id=uuid4(),
                raw_input="ls",
                raw_output="files...",
                interaction_type=InteractionType.COMMAND,
            ),
        ]
        profile = await profiler.fingerprint("10.0.0.1", interactions)
        assert profile.sophistication == SophisticationLevel.SCRIPT_KIDDIE

    @pytest.mark.asyncio
    async def test_sophistication_intermediate(self) -> None:
        """Test classification of intermediate attacker."""
        profiler = AttackerProfiler()
        interactions = [
            InteractionLog(
                id=uuid4(),
                session_id=uuid4(),
                attacker_id=uuid4(),
                honeypot_id=uuid4(),
                raw_input="nmap -sS 10.0.0.0/24",
                raw_output="Starting Nmap...",
                interaction_type=InteractionType.COMMAND,
            ),
        ]
        profile = await profiler.fingerprint("10.0.0.1", interactions)
        assert profile.sophistication == SophisticationLevel.INTERMEDIATE

    @pytest.mark.asyncio
    async def test_intent_recon(self) -> None:
        """Test recon intent detection."""
        profiler = AttackerProfiler()
        interactions = [
            InteractionLog(
                id=uuid4(),
                session_id=uuid4(),
                attacker_id=uuid4(),
                honeypot_id=uuid4(),
                raw_input="nmap",
                raw_output="scan results...",
                interaction_type=InteractionType.COMMAND,
            ),
        ]
        profile = await profiler.fingerprint("10.0.0.1", interactions)
        assert IntentType.RECON in profile.intent

    @pytest.mark.asyncio
    async def test_get_profile(self) -> None:
        """Test profile retrieval by ID."""
        profiler = AttackerProfiler()
        interactions = [
            InteractionLog(
                id=uuid4(),
                session_id=uuid4(),
                attacker_id=uuid4(),
                honeypot_id=uuid4(),
                raw_input="whoami",
                raw_output="root",
                interaction_type=InteractionType.COMMAND,
            ),
        ]
        profile = await profiler.fingerprint("10.0.0.1", interactions)
        found = await profiler.get_profile(profile.id)
        assert found is not None
        assert found.id == profile.id

    @pytest.mark.asyncio
    async def test_get_profile_by_ip(self) -> None:
        """Test profile lookup by IP."""
        profiler = AttackerProfiler()
        interactions = [
            InteractionLog(
                id=uuid4(),
                session_id=uuid4(),
                attacker_id=uuid4(),
                honeypot_id=uuid4(),
                raw_input="id",
                raw_output="uid=0(root)",
                interaction_type=InteractionType.COMMAND,
            ),
        ]
        profile = await profiler.fingerprint("10.0.0.99", interactions)
        found = await profiler.get_profile_by_ip("10.0.0.99")
        assert found is not None
        assert found.id == profile.id

    @pytest.mark.asyncio
    async def test_list_profiles(self) -> None:
        """Test listing all profiles."""
        profiler = AttackerProfiler()
        for i in range(3):
            interactions = [
                InteractionLog(
                    id=uuid4(),
                    session_id=uuid4(),
                    attacker_id=uuid4(),
                    honeypot_id=uuid4(),
                    raw_input=f"cmd{i}",
                    raw_output=f"out{i}",
                    interaction_type=InteractionType.COMMAND,
                ),
            ]
            await profiler.fingerprint(f"10.0.0.{i}", interactions)

        profiles = await profiler.list_profiles()
        assert len(profiles) == 3

    @pytest.mark.asyncio
    async def test_threat_score_calculation(self) -> None:
        """Test threat score is calculated."""
        profiler = AttackerProfiler()
        interactions = [
            InteractionLog(
                id=uuid4(),
                session_id=uuid4(),
                attacker_id=uuid4(),
                honeypot_id=uuid4(),
                raw_input="nmap -sS target",
                raw_output="scan results...",
                interaction_type=InteractionType.COMMAND,
            ),
        ]
        profile = await profiler.fingerprint("10.0.0.1", interactions)
        assert 0 <= profile.threat_score <= 100
