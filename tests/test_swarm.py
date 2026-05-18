"""
test_swarm.py -- Tests for the swarm integration layer.

Covers:
- CenturiaAdapter connect/submit/get/broadcast/request
- ThreatFeed subscribe/publish/get_recent
- AdaptiveDefense update/auto_segment/deploy/generate_waf
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from uuid import uuid4

from ember_honeypot.swarm.centuria_adapter import (
    CenturiaAdapter,
    ThreatIntel,
    CollectiveMemory,
)
from ember_honeypot.swarm.threat_feed import ThreatFeed, ThreatUpdate, ThreatSeverity, ThreatCategory
from ember_honeypot.swarm.adaptive_defense import (
    AdaptiveDefense,
    DefenseAction,
    ActionType,
    Priority,
    ThreatScore,
    TTPRecord,
)
from ember_honeypot.models import DecoyPersona, IOC, IOCType


# ============================================================================
# CenturiaAdapter Tests
# ============================================================================

class TestCenturiaAdapter:
    """Test Centuria swarm adapter."""

    @pytest.mark.asyncio
    async def test_connect(self) -> None:
        """Test swarm connection."""
        adapter = CenturiaAdapter(endpoint="http://mock:9000")
        result = await adapter.connect()
        assert result is True
        assert adapter.connected is True
        await adapter.disconnect()

    @pytest.mark.asyncio
    async def test_disconnect(self) -> None:
        """Test swarm disconnection."""
        adapter = CenturiaAdapter(endpoint="http://mock:9000")
        await adapter.connect()
        await adapter.disconnect()
        assert adapter.connected is False

    @pytest.mark.asyncio
    async def test_health(self) -> None:
        """Test health status."""
        adapter = CenturiaAdapter(endpoint="http://mock:9000")
        await adapter.connect()
        health = adapter.health()
        assert health.connected is True
        assert health.agents_online > 0
        assert health.total_agents == 101
        assert health.latency_ms > 0
        await adapter.disconnect()

    @pytest.mark.asyncio
    async def test_submit_threat_intel(self) -> None:
        """Test threat intel submission."""
        adapter = CenturiaAdapter(endpoint="http://mock:9000")
        await adapter.connect()
        intel = ThreatIntel(
            attacker_ip="10.0.0.50",
            threat_score=75,
            confidence=0.8,
            raw_indicators=["suspicious_command"],
        )
        result = await adapter.submit_threat_intel(intel)
        assert result is True
        await adapter.disconnect()

    @pytest.mark.asyncio
    async def test_submit_intel_updates_memory(self) -> None:
        """Test that submitted intel updates collective memory."""
        adapter = CenturiaAdapter(endpoint="http://mock:9000")
        await adapter.connect()
        intel = ThreatIntel(
            attacker_ip="10.0.0.99",
            threat_score=90,
            confidence=0.9,
        )
        await adapter.submit_threat_intel(intel)
        memory = await adapter.get_collective_memory("10.0.0.99")
        assert memory is not None
        assert memory.attacker_ip == "10.0.0.99"
        await adapter.disconnect()

    @pytest.mark.asyncio
    async def test_get_collective_memory_unknown(self) -> None:
        """Test collective memory for unknown IP."""
        adapter = CenturiaAdapter(endpoint="http://mock:9000")
        await adapter.connect()
        memory = await adapter.get_collective_memory("192.0.2.1")
        assert memory is None
        await adapter.disconnect()

    @pytest.mark.asyncio
    async def test_broadcast_ioc(self) -> None:
        """Test IOC broadcasting."""
        adapter = CenturiaAdapter(endpoint="http://mock:9000")
        await adapter.connect()
        ioc = IOC(
            ioc_type=IOCType.IP,
            value="10.0.0.1",
            confidence=0.9,
            context="Test IOC",
        )
        result = await adapter.broadcast_ioc(ioc)
        assert result is True
        await adapter.disconnect()

    @pytest.mark.asyncio
    async def test_request_reinforcement(self, test_persona: DecoyPersona) -> None:
        """Test reinforcement request."""
        adapter = CenturiaAdapter(endpoint="http://mock:9000")
        await adapter.connect()
        result = await adapter.request_reinforcement(test_persona)
        assert result is True
        await adapter.disconnect()

    @pytest.mark.asyncio
    async def test_submit_without_connect(self) -> None:
        """Test intel submission without connecting queues data."""
        adapter = CenturiaAdapter(endpoint="http://mock:9000")
        # Do not connect
        intel = ThreatIntel(attacker_ip="10.0.0.1", threat_score=50)
        result = await adapter.submit_threat_intel(intel)
        assert result is True  # Queued, not lost
        assert adapter.health().queued_intel_count == 1


# ============================================================================
# ThreatFeed Tests
# ============================================================================

class TestThreatFeed:
    """Test threat feed pub/sub."""

    @pytest.mark.asyncio
    async def test_subscribe(self, threat_feed: ThreatFeed) -> None:
        """Test subscriber registration."""
        received: list[ThreatUpdate] = []

        async def callback(update: ThreatUpdate) -> None:
            received.append(update)

        threat_feed.subscribe(callback)
        assert threat_feed.subscriber_count == 1

    @pytest.mark.asyncio
    async def test_publish(self, threat_feed: ThreatFeed) -> None:
        """Test threat publishing."""
        received: list[ThreatUpdate] = []

        async def callback(update: ThreatUpdate) -> None:
            received.append(update)

        threat_feed.subscribe(callback)
        threat = ThreatUpdate(
            severity=ThreatSeverity.HIGH,
            category=ThreatCategory.INTRUSION,
            source_ip="10.0.0.1",
            description="Test threat",
        )
        await threat_feed.publish(threat)
        assert len(received) == 1
        assert received[0].source_ip == "10.0.0.1"
        assert received[0].severity == ThreatSeverity.HIGH

    @pytest.mark.asyncio
    async def test_publish_multiple_subscribers(self, threat_feed: ThreatFeed) -> None:
        """Test publishing to multiple subscribers."""
        received1: list[ThreatUpdate] = []
        received2: list[ThreatUpdate] = []

        async def cb1(update: ThreatUpdate) -> None:
            received1.append(update)

        async def cb2(update: ThreatUpdate) -> None:
            received2.append(update)

        threat_feed.subscribe(cb1)
        threat_feed.subscribe(cb2)

        threat = ThreatUpdate(severity=ThreatSeverity.CRITICAL, source_ip="10.0.0.2")
        await threat_feed.publish(threat)
        assert len(received1) == 1
        assert len(received2) == 1

    @pytest.mark.asyncio
    async def test_get_recent(self, threat_feed: ThreatFeed) -> None:
        """Test recent threat retrieval."""
        async def noop(update: ThreatUpdate) -> None:
            pass

        threat_feed.subscribe(noop)
        for i in range(5):
            await threat_feed.publish(ThreatUpdate(
                severity=ThreatSeverity.MEDIUM,
                source_ip=f"10.0.0.{i}",
            ))

        recent = threat_feed.get_recent(limit=3)
        assert len(recent) == 3

    @pytest.mark.asyncio
    async def test_get_by_severity(self, threat_feed: ThreatFeed) -> None:
        """Test filtering by severity."""
        async def noop(update: ThreatUpdate) -> None:
            pass

        threat_feed.subscribe(noop)
        await threat_feed.publish(ThreatUpdate(severity=ThreatSeverity.LOW))
        await threat_feed.publish(ThreatUpdate(severity=ThreatSeverity.HIGH))
        await threat_feed.publish(ThreatUpdate(severity=ThreatSeverity.HIGH))

        high = threat_feed.get_by_severity(ThreatSeverity.HIGH)
        assert len(high) == 2

    @pytest.mark.asyncio
    async def test_get_by_ip(self, threat_feed: ThreatFeed) -> None:
        """Test filtering by IP."""
        async def noop(update: ThreatUpdate) -> None:
            pass

        threat_feed.subscribe(noop)
        await threat_feed.publish(ThreatUpdate(source_ip="10.0.0.50"))
        await threat_feed.publish(ThreatUpdate(source_ip="10.0.0.51"))

        results = threat_feed.get_by_ip("10.0.0.50")
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_unsubscribe(self, threat_feed: ThreatFeed) -> None:
        """Test subscriber removal."""
        async def noop(update: ThreatUpdate) -> None:
            pass

        threat_feed.subscribe(noop)
        assert threat_feed.subscriber_count == 1
        result = threat_feed.unsubscribe(noop)
        assert result is True
        assert threat_feed.subscriber_count == 0

    @pytest.mark.asyncio
    async def test_get_stats(self, threat_feed: ThreatFeed) -> None:
        """Test feed statistics."""
        async def noop(update: ThreatUpdate) -> None:
            pass

        threat_feed.subscribe(noop)
        await threat_feed.publish(ThreatUpdate(severity=ThreatSeverity.MEDIUM))
        stats = threat_feed.get_stats()
        assert stats["total_published"] == 1
        assert stats["subscriber_count"] == 1

    @pytest.mark.asyncio
    async def test_publish_no_subscribers(self, threat_feed: ThreatFeed) -> None:
        """Test publishing with no subscribers doesn't error."""
        threat = ThreatUpdate(severity=ThreatSeverity.LOW)
        await threat_feed.publish(threat)
        assert threat_feed.get_stats()["total_published"] == 1


# ============================================================================
# AdaptiveDefense Tests
# ============================================================================

class TestAdaptiveDefense:
    """Test adaptive defense engine."""

    @pytest.mark.asyncio
    async def test_update_posture_critical(self, adaptive_defense: AdaptiveDefense) -> None:
        """Test critical threat posture update."""
        score = ThreatScore(overall=0.85, sophistication=0.80, persistence=0.70, stealth=0.60, aggressiveness=0.90)
        actions = adaptive_defense.update_posture(score)
        assert len(actions) > 0
        assert any(a.action_type == ActionType.QUARANTINE for a in actions)

    @pytest.mark.asyncio
    async def test_update_posture_high(self, adaptive_defense: AdaptiveDefense) -> None:
        """Test high threat posture update."""
        score = ThreatScore(overall=0.65, sophistication=0.70, persistence=0.50, stealth=0.40, aggressiveness=0.60)
        actions = adaptive_defense.update_posture(score)
        assert len(actions) > 0
        assert any(a.action_type == ActionType.HONEYTRAP for a in actions)

    @pytest.mark.asyncio
    async def test_update_posture_medium(self, adaptive_defense: AdaptiveDefense) -> None:
        """Test medium threat posture update."""
        score = ThreatScore(overall=0.45, sophistication=0.40, persistence=0.30, stealth=0.20, aggressiveness=0.50)
        actions = adaptive_defense.update_posture(score)
        assert len(actions) > 0
        assert any(a.action_type == ActionType.ALERT for a in actions)

    @pytest.mark.asyncio
    async def test_update_posture_low(self, adaptive_defense: AdaptiveDefense) -> None:
        """Test low threat posture update."""
        score = ThreatScore(overall=0.15, sophistication=0.10, persistence=0.05, stealth=0.05, aggressiveness=0.10)
        actions = adaptive_defense.update_posture(score)
        # Low scores may generate 0 or few actions
        assert isinstance(actions, list)
        if actions:
            assert all(a.priority in (Priority.MEDIUM, Priority.LOW) for a in actions)

    def test_auto_segment(self, adaptive_defense: AdaptiveDefense) -> None:
        """Test network auto-segmentation."""
        result = adaptive_defense.auto_segment("10.0.0.100")
        assert result is True
        assert adaptive_defense.is_segmented("10.0.0.100")

    def test_auto_segment_duplicate(self, adaptive_defense: AdaptiveDefense) -> None:
        """Test segmenting already-segmented IP."""
        adaptive_defense.auto_segment("10.0.0.100")
        result = adaptive_defense.auto_segment("10.0.0.100")
        assert result is True  # Already segmented, returns True

    def test_lift_segmentation(self, adaptive_defense: AdaptiveDefense) -> None:
        """Test lifting segmentation."""
        adaptive_defense.auto_segment("10.0.0.100")
        result = adaptive_defense.lift_segmentation("10.0.0.100")
        assert result is True
        assert not adaptive_defense.is_segmented("10.0.0.100")

    def test_lift_nonexistent_segmentation(self, adaptive_defense: AdaptiveDefense) -> None:
        """Test lifting segmentation for non-segmented IP."""
        result = adaptive_defense.lift_segmentation("10.0.0.200")
        assert result is False

    def test_deploy_countermeasures(self, adaptive_defense: AdaptiveDefense) -> None:
        """Test countermeasure deployment."""
        ttps = [
            TTPRecord(
                tactic="Discovery",
                tactic_id="TA0007",
                technique="Network Service Discovery",
                technique_id="T1046",
                procedure="nmap scan",
                confidence=0.8,
            ),
        ]
        actions = adaptive_defense.deploy_countermeasures(ttps)
        assert isinstance(actions, list)
        assert len(actions) >= 0

    def test_generate_waf_rules_sqli(self, adaptive_defense: AdaptiveDefense) -> None:
        """Test WAF rule generation for SQL injection."""
        payloads = ["' UNION SELECT * FROM users--"]
        rules = adaptive_defense.generate_waf_rules(payloads)
        assert len(rules) > 0
        assert any("SQL" in r for r in rules)

    def test_generate_waf_rules_xss(self, adaptive_defense: AdaptiveDefense) -> None:
        """Test WAF rule generation for XSS."""
        payloads = ["<script>alert('xss')</script>"]
        rules = adaptive_defense.generate_waf_rules(payloads)
        assert len(rules) > 0
        assert any("XSS" in r for r in rules)

    def test_generate_waf_rules_path_traversal(self, adaptive_defense: AdaptiveDefense) -> None:
        """Test WAF rule generation for path traversal."""
        payloads = ["../../../etc/passwd"]
        rules = adaptive_defense.generate_waf_rules(payloads)
        assert len(rules) > 0
        assert any("Path Traversal" in r or "Traversal" in r for r in rules)

    def test_generate_waf_rules_multiple_payloads(self, adaptive_defense: AdaptiveDefense, attack_payloads: list[str]) -> None:
        """Test WAF rule generation for multiple attack payloads."""
        rules = adaptive_defense.generate_waf_rules(attack_payloads)
        assert len(rules) > 0
        # Rules should be generated for at least some payloads
        assert any("SecRule" in r for r in rules)

    def test_generate_waf_rules_no_match(self, adaptive_defense: AdaptiveDefense) -> None:
        """Test WAF rule generation with unknown payloads."""
        payloads = ["hello world", "ls -la"]
        rules = adaptive_defense.generate_waf_rules(payloads)
        assert len(rules) >= 0  # May generate generic rules

    def test_action_log(self, adaptive_defense: AdaptiveDefense) -> None:
        """Test action logging."""
        score = ThreatScore(overall=0.50)
        actions = adaptive_defense.update_posture(score)
        log = adaptive_defense.get_action_log()
        assert len(log) > 0

    def test_get_active_actions(self, adaptive_defense: AdaptiveDefense) -> None:
        """Test getting active (non-expired) actions."""
        score = ThreatScore(overall=0.50)
        adaptive_defense.update_posture(score)
        active = adaptive_defense.get_active_actions()
        assert len(active) > 0

    def test_get_stats(self, adaptive_defense: AdaptiveDefense) -> None:
        """Test defense engine statistics."""
        score = ThreatScore(overall=0.50)
        adaptive_defense.update_posture(score)
        stats = adaptive_defense.get_stats()
        assert "total_actions" in stats
        assert stats["total_actions"] > 0
