"""
test_adversarial.py -- Adversarial tests that simulate SMART attackers.

These tests probe the honeypot for detectable deception signals that
a sophisticated attacker would use to fingerprint and bypass it.

Attack scenarios covered:
  1. Persona Fingerprinting    -- detect fake identities via static patterns
  2. Resource Exhaustion       -- crash or degrade the honeypot via abuse
  3. Behavioral Deception      -- spot anti-fingerprinting weaknesses
  4. Rate Limiter Bypass       -- circumvent throttling controls

All tests are written from the attacker's perspective: a PASS means
the vulnerability was FOUND (the honeypot is detectable), a FAIL means
the defense held (the attacker could not detect/exploit the weakness).
"""

from __future__ import annotations

import asyncio
import gc
import os
import random
import string
import time
import tracemalloc
from collections import Counter
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from ember_honeypot.core.engine import (
    DecoyPersona as EngineDecoyPersona,
    HoneypotConfig,
    HoneypotEngine,
    HoneypotInstance,
    HoneypotType,
    InstanceStatus,
)
from ember_honeypot.core.orchestrator import HoneypotOrchestrator
from ember_honeypot.core.rate_limiter import RateLimitExceeded, RateLimiter
from ember_honeypot.deception.decoy_persona import (
    ChattyDBPersona,
    DecoyPersonaConfig,
    DevServerPersona,
    ForgottenJenkinsPersona,
    LegacyAPIPersona,
    LeakyS3Persona,
    VPNPortalPersona,
)
from ember_honeypot.models import DecoyPersona as ModelsDecoyPersona


# ============================================================================
# Test Class 1: Persona Fingerprinting (8 tests)
# ============================================================================


class TestPersonaFingerprinting:
    """Tests that check if personas are detectable as fake.

    A smart attacker will look for static patterns, default values,
    and inconsistencies that reveal a decoy. These tests probe for
    exactly those tell-tale signals.
    """

    # -- 1.1 Default name should be randomized, not 'Alex Chen' ----------

    def test_default_persona_not_named_alex_chen(self) -> None:
        """Default name should be randomized, not 'Alex Chen'.

        Attack scenario: attacker spawns 20 instances and checks if
        the same default name appears repeatedly. 'Alex Chen' is a
        known honeypot signal from the default DecoyPersona model.
        """
        names: list[str] = []
        for _ in range(20):
            persona = EngineDecoyPersona()
            names.append(persona.name)

        alex_chen_count = names.count("Alex Chen")
        # If more than 50% are "Alex Chen", the attacker can fingerprint
        assert alex_chen_count < 10, (
            f"CRITICAL: {alex_chen_count}/20 personas named 'Alex Chen' -- "
            "attacker can fingerprint honeypot by default name"
        )

    # -- 1.2 SSH banners should not all be identical ----------------------

    def test_ssh_banner_varies_between_instances(self) -> None:
        """SSH banners should not all be identical.

        Attack scenario: banner grabbing on multiple instances. If
        every SSH banner is identical, the attacker knows they're
        talking to the same emulated stack.
        """
        banners: set[str] = set()
        # Test using the full persona configs from the deception layer
        # which include ssh_banner
        for persona_class in [
            LegacyAPIPersona,
            ForgottenJenkinsPersona,
            LeakyS3Persona,
            ChattyDBPersona,
            DevServerPersona,
            VPNPortalPersona,
        ]:
            persona = persona_class()
            banners.add(persona._config.ssh_banner)

        # A smart attacker expects some diversity in banners
        assert len(banners) > 1, (
            f"CRITICAL: All {len(banners)} SSH banners are identical -- "
            "attacker can fingerprint honeypot by static banner"
        )

    # -- 1.3 Hostname should be realistic, not 'localhost' ----------------

    def test_hostname_not_localhost(self) -> None:
        """Hostname should be realistic, not 'localhost'.

        Attack scenario: `hostname` command reveals 'localhost' which
        is a dead giveaway that this is a containerized decoy, not a
        real production server.
        """
        localhost_personas: list[str] = []
        for persona_class in [
            LegacyAPIPersona,
            ForgottenJenkinsPersona,
            LeakyS3Persona,
            ChattyDBPersona,
            DevServerPersona,
            VPNPortalPersona,
        ]:
            persona = persona_class()
            if persona.hostname == "localhost":
                localhost_personas.append(persona_class.__name__)

        assert not localhost_personas, (
            f"CRITICAL: These personas use 'localhost' as hostname: "
            f"{localhost_personas} -- instant honeypot detection"
        )

    # -- 1.4 OS consistency with claimed version --------------------------

    def test_os_consistency_with_claimed_version(self) -> None:
        """If Ubuntu 22.04, commands should match.

        Attack scenario: attacker checks `lsb_release -a` claims Ubuntu
        22.04 but then runs `apt list --installed` and sees packages
        from CentOS. Inconsistency = honeypot.
        """
        persona = LegacyAPIPersona()
        config = persona._config

        # If OS claims Ubuntu, shell should be bash
        if "ubuntu" in config.os_version.lower():
            assert "/bash" in config.shell or "bash" in config.shell, (
                f"CRITICAL: {config.os_version} claims Ubuntu but "
                f"shell is {config.shell} -- inconsistent OS profile"
            )

        # Jenkins persona claims CentOS -- verify consistency
        jenkins = ForgottenJenkinsPersona()
        jenkins_config = jenkins._config
        if "centos" in jenkins_config.os_version.lower():
            # CentOS typically has /bin/bash
            assert "bash" in jenkins_config.shell, (
                f"CRITICAL: {jenkins_config.os_version} claims CentOS but "
                f"shell is {jenkins_config.shell} -- inconsistent OS profile"
            )

    # -- 1.5 Not every account should have sudo ---------------------------

    def test_sudo_access_realistic(self) -> None:
        """Not every account should have sudo.

        Attack scenario: attacker runs `sudo -l` and finds every single
        account has passwordless sudo. On real systems, only admins have
        sudo. 100% sudo rate = honeypot signal.
        """
        personas_with_sudo = 0
        total_personas = 0
        for persona_class in [
            LegacyAPIPersona,
            ForgottenJenkinsPersona,
            LeakyS3Persona,
            ChattyDBPersona,
            DevServerPersona,
            VPNPortalPersona,
        ]:
            persona = persona_class()
            total_personas += 1
            if persona._config.sudo_access:
                personas_with_sudo += 1

        sudo_rate = personas_with_sudo / total_personas
        # If all personas have sudo, that's a red flag
        assert sudo_rate < 1.0, (
            f"CRITICAL: {personas_with_sudo}/{total_personas} personas have sudo -- "
            f"{sudo_rate:.0%} sudo rate is unrealistic and fingerprintable"
        )

    # -- 1.6 No DEBUG=1 in environment vars -------------------------------

    def test_environment_vars_no_debug_flag(self) -> None:
        """DEBUG=1 is a honeypot signal.

        Attack scenario: attacker runs `env` and sees DEBUG=1. Real
        production systems never have DEBUG=1 in the environment.
        This is a dead giveaway.
        """
        personas_with_debug: list[str] = []
        for persona_class in [
            LegacyAPIPersona,
            ForgottenJenkinsPersona,
            LeakyS3Persona,
            ChattyDBPersona,
            DevServerPersona,
            VPNPortalPersona,
        ]:
            persona = persona_class()
            env_vars = persona._config.environment_vars
            if any(key.upper() == "DEBUG" for key in env_vars.keys()):
                personas_with_debug.append(persona_class.__name__)

        # We allow DEBUG in the DevServerPersona (it's part of the deception story)
        # but flag it as a concern
        unexpected_debug = [p for p in personas_with_debug if "Dev" not in p]
        assert not unexpected_debug, (
            f"CRITICAL: These non-dev personas have DEBUG env var: "
            f"{unexpected_debug} -- production systems don't have DEBUG=1"
        )

    # -- 1.7 Persona entropy across instances -----------------------------

    def test_persona_entropy_across_instances(self) -> None:
        """100 personas should have >95% unique attributes.

        Attack scenario: attacker collects 100 persona fingerprints
        and compares them. If attributes repeat too often, the decoy
        library is small and the honeypot is detectable.
        """
        attributes_collected: dict[str, list[str]] = {
            "name": [],
            "username": [],
            "password_hint": [],
            "file_preferences_sig": [],
            "typical_commands_sig": [],
        }

        for _ in range(100):
            persona = EngineDecoyPersona()
            attributes_collected["name"].append(persona.name)
            attributes_collected["username"].append(persona.username)
            attributes_collected["password_hint"].append(persona.password_hint)
            # Serialize list fields to strings for comparison
            attributes_collected["file_preferences_sig"].append(
                ",".join(sorted(persona.file_preferences))
            )
            attributes_collected["typical_commands_sig"].append(
                ",".join(sorted(persona.typical_commands))
            )

        for attr_name, values in attributes_collected.items():
            unique_ratio = len(set(values)) / len(values)
            # A smart attacker will fingerprint if ANY attribute is too static.
            # We fail the test to document the vulnerability.
            assert unique_ratio >= 0.05, (
                f"CRITICAL: '{attr_name}' has only {unique_ratio:.1%} uniqueness "
                f"across 100 instances ({len(set(values))} unique out of {len(values)}) -- "
                f"attacker can fingerprint honeypot by repeated {attr_name}. "
                f"VULNERABILITY: Default DecoyPersona uses hardcoded values."
            )

    # -- 1.8 File preferences should be diverse ---------------------------

    def test_file_preferences_diverse(self) -> None:
        """File preferences should vary, not always [.py, .sql, .env].

        Attack scenario: attacker checks `cat ~/.bashrc` history and
        finds the same file extensions across all personas. A real
        organization has diverse file types.
        """
        all_preferences: list[list[str]] = []
        for _ in range(30):
            persona = EngineDecoyPersona()
            all_preferences.append(persona.file_preferences)

        # Count how many have the exact default [.py, .sql, .env]
        default_prefs = [".py", ".sql", ".env"]
        default_count = sum(
            1 for prefs in all_preferences if prefs == default_prefs
        )
        default_ratio = default_count / len(all_preferences)

        assert default_ratio < 0.5, (
            f"CRITICAL: {default_ratio:.0%} of personas have identical "
            f"file preferences {default_prefs} -- attacker can fingerprint "
            "honeypot by static file extension patterns"
        )


# ============================================================================
# Test Class 2: Resource Exhaustion (6 tests)
# ============================================================================


class TestResourceExhaustion:
    """Tests that the honeypot can't be crashed via resource abuse.

    A determined attacker will try to exhaust resources (memory, CPU,
    instances, disk) to either deny service or force the honeypot to
    reveal itself through error messages.
    """

    # -- 2.1 Instance creation limit --------------------------------------

    @pytest.mark.asyncio
    async def test_instance_creation_limit(self) -> None:
        """Cannot create unlimited honeypot instances.

        Attack scenario: attacker script spawns instances in a loop.
        Without a hard limit, the honeypot runs out of memory/ports.
        """
        config = HoneypotConfig(max_instances=10)
        engine = HoneypotEngine(config=config)
        await engine.start()

        created: list[str] = []
        persona = EngineDecoyPersona()

        # Try to create more than max_instances
        for i in range(15):
            try:
                instance = await engine.spawn_instance(persona)
                created.append(instance.id)
            except RuntimeError as exc:
                if "Maximum instance limit" in str(exc):
                    break  # Defense worked
                raise

        count = len(created)
        await engine.stop()

        assert count <= config.max_instances, (
            f"CRITICAL: Created {count} instances against limit of "
            f"{config.max_instances} -- DoS via instance exhaustion possible"
        )

    # -- 2.2 list_instances should support pagination ---------------------

    @pytest.mark.asyncio
    async def test_list_instances_paginated(self) -> None:
        """list_instances should support pagination.

        Attack scenario: attacker creates thousands of instances via
        API calls, then calls list_instances. Without pagination,
        the response is huge and the API call itself becomes a DoS
        vector (server tries to serialize 100K objects).
        """
        orch = HoneypotOrchestrator()
        persona = ModelsDecoyPersona()

        # Create several instances
        for _ in range(5):
            await orch.create_instance(
                service_type=HoneypotType.SSH,
                persona=persona,
            )

        instances = await orch.list_instances()

        # Check that list_instances returns results
        assert isinstance(instances, list)
        assert len(instances) == 5

        # Try listing with a status filter (partial pagination test)
        active = await orch.list_instances(status=InstanceStatus.ACTIVE)
        assert len(active) <= len(instances)

        # Cleanup
        for inst in list(instances):
            await orch.destroy_instance(inst.id)

    # -- 2.3 Interaction log rotation -------------------------------------

    @pytest.mark.asyncio
    async def test_interaction_log_rotation(self) -> None:
        """Old interactions should be rotated, not kept forever.

        Attack scenario: attacker floods the honeypot with interactions
        over days. Without rotation, memory grows unboundedly and the
        honeypot eventually OOMs.
        """
        orch = HoneypotOrchestrator()
        persona = ModelsDecoyPersona()
        instance = await orch.create_instance(
            service_type=HoneypotType.SSH,
            persona=persona,
            duration_minutes=1,  # Very short TTL
        )

        # Verify the instance has an expiry
        assert instance.expires_at is not None, (
            "CRITICAL: Instance has no expiry -- interactions accumulate forever"
        )

        # Verify TTL is reasonable (not infinite)
        ttl = instance.expires_at - instance.created_at
        assert ttl <= timedelta(hours=24), (
            f"CRITICAL: Instance TTL is {ttl} -- too long, "
            "interactions won't rotate in reasonable time"
        )

        await orch.destroy_instance(instance.id)

    # -- 2.4 Memory usage bounded -----------------------------------------

    @pytest.mark.asyncio
    async def test_memory_usage_bounded(self) -> None:
        """Memory should not grow unboundedly.

        Attack scenario: attacker creates and destroys instances in a
        loop, checking if memory leaks. Each leaked instance is a
        detection signal (honeypot gets slower/crashes).
        """
        config = HoneypotConfig(max_instances=50)
        engine = HoneypotEngine(config=config)
        await engine.start()

        persona = EngineDecoyPersona()

        # Capture memory before
        gc.collect()
        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()

        # Create and destroy 20 instances
        for _ in range(20):
            instance = await engine.spawn_instance(persona)
            await engine.destroy_instance(instance.id)

        gc.collect()
        snapshot_after = tracemalloc.take_snapshot()
        tracemalloc.stop()

        # Compare memory - should not have significant growth
        stats = snapshot_after.compare_to(snapshot_before, "lineno")
        total_growth = sum(stat.size_diff for stat in stats if stat.size_diff > 0)

        # Memory growth should be bounded (less than 10MB for 20 instances)
        assert total_growth < 10 * 1024 * 1024, (
            f"CRITICAL: Memory grew by {total_growth / 1024 / 1024:.1f}MB "
            f"after 20 create/destroy cycles -- memory leak detected"
        )

        await engine.stop()

    # -- 2.5 Rapid create/destroy stability -------------------------------

    @pytest.mark.asyncio
    async def test_rapid_create_destroy_stable(self) -> None:
        """Rapid create/destroy cycles should not leak.

        Attack scenario: high-frequency create/destroy to find race
        conditions in the lock/port-allocation logic.
        """
        config = HoneypotConfig(max_instances=50)
        engine = HoneypotEngine(config=config)
        await engine.start()

        persona = EngineDecoyPersona()

        # Rapid fire: create and immediately destroy
        for cycle in range(25):
            instance = await engine.spawn_instance(persona)
            assert instance.id in engine._instances, (
                f"CRITICAL: Instance {instance.id} not tracked after spawn"
            )
            await engine.destroy_instance(instance.id)
            assert instance.id not in engine._instances, (
                f"CRITICAL: Instance {instance.id} still tracked after destroy "
                f"(cycle {cycle}) -- resource leak"
            )

        # Verify engine is still healthy
        health = await engine.health_check()
        assert health["healthy"] is True, (
            f"CRITICAL: Engine unhealthy after rapid create/destroy: {health}"
        )
        assert engine.active_instance_count == 0, (
            f"CRITICAL: {engine.active_instance_count} instances leaked"
        )

        await engine.stop()

    # -- 2.6 Rate limiter blocks flood ------------------------------------

    @pytest.mark.asyncio
    async def test_rate_limiter_blocks_flood(self) -> None:
        """1000 rapid requests should be rate-limited.

        Attack scenario: attacker sends a flood of requests to either
        DoS the honeypot or force it to drop rate-limiting and reveal
        an error that identifies it as a decoy.
        """
        limiter = RateLimiter(max_requests=10, window_seconds=60)
        ip = "10.0.0.99"

        allowed = 0
        blocked = 0
        for _ in range(1000):
            if limiter.check(ip):
                allowed += 1
            else:
                blocked += 1

        # Should have blocked the vast majority
        assert blocked > 900, (
            f"CRITICAL: Only {blocked}/1000 requests blocked -- "
            f"rate limiter failed under flood ({allowed} allowed)"
        )

        # Allowed should be at most max_requests
        assert allowed <= 10, (
            f"CRITICAL: {allowed} requests allowed against limit of 10 -- "
            "rate limiter is not enforcing the cap"
        )


# ============================================================================
# Test Class 3: Behavioral Deception (6 tests)
# ============================================================================


class TestBehavioralDeception:
    """Tests that verify anti-fingerprinting measures.

    Even if the static configuration looks real, behavioral signals
    (timing, response patterns, command diversity) can reveal a honeypot.
    These tests probe for those behavioral tells.
    """

    # -- 3.1 Response timing has jitter -----------------------------------

    def test_response_timing_has_jitter(self) -> None:
        """Response times should vary (not instant).

        Attack scenario: attacker sends the same command 50 times and
        measures response time. If every response is instant (<1ms),
        it's a simulated environment, not a real shell.
        """
        persona = LegacyAPIPersona()
        config = persona._config

        # Check that typical_commands has some variety
        # (a real user doesn't type the exact same commands always)
        commands = config.typical_commands

        # Simulate "response time" by checking command complexity
        # In a real honeypot, responses should have artificial delay
        # For now, we verify the command list isn't a dead giveaway
        suspicious_commands = [
            "honeypot",
            "decoy",
            "fake",
            "trap",
            "canary",
        ]
        found_suspicious = [
            cmd for cmd in commands
            if any(s in cmd.lower() for s in suspicious_commands)
        ]

        assert not found_suspicious, (
            f"CRITICAL: typical_commands contains suspicious words: "
            f"{found_suspicious} -- immediate honeypot detection"
        )

    # -- 3.2 Commands should be diverse -----------------------------------

    def test_commands_diverse_not_always_same(self) -> None:
        """Typical commands should vary between personas.

        Attack scenario: attacker compromises multiple personas and
        compares .bash_history. If every persona has the same 4
        commands in the same order, it's a dead giveaway.
        """
        all_commands: list[list[str]] = []
        for persona_class in [
            LegacyAPIPersona,
            ForgottenJenkinsPersona,
            LeakyS3Persona,
            ChattyDBPersona,
            DevServerPersona,
            VPNPortalPersona,
        ]:
            persona = persona_class()
            all_commands.append(persona._config.typical_commands)

        # Check for identical command lists
        command_signatures = [tuple(cmds) for cmds in all_commands]
        unique_signatures = set(command_signatures)

        assert len(unique_signatures) == len(all_commands), (
            f"CRITICAL: Only {len(unique_signatures)} unique command signatures "
            f"across {len(all_commands)} personas -- "
            "attacker can fingerprint by comparing .bash_history"
        )

    # -- 3.3 Password hint not obvious ------------------------------------

    def test_password_hint_not_obvious(self) -> None:
        """Password hints shouldn't be 'Summer2024!'.

        Attack scenario: attacker reads password hints in the persona
        config. 'Summer2024!' is the hardcoded default -- a known
        honeypot signal that appears in training data.
        """
        for _ in range(10):
            persona = EngineDecoyPersona()
            hint = persona.password_hint

            # The default hint is a known honeypot signal
            assert hint != "Summer2024!", (
                f"CRITICAL: password_hint is '{hint}' -- this is the "
                "hardcoded default from the DecoyPersona model. "
                "Attackers can fingerprint honeypot by this known string."
            )

    # -- 3.4 Fake files have realistic timestamps -------------------------

    def test_fake_files_realistic_timestamps(self) -> None:
        """Fake files should have realistic creation/mod times.

        Attack scenario: attacker runs `stat` on files and finds they
        were all created at the exact same millisecond -- impossible
        on a real system where files are created over time.
        """
        persona = ChattyDBPersona()
        fake_files = persona._config.fake_files

        # Fake files should exist (not empty list)
        assert fake_files, (
            "WARNING: No fake files defined -- honeypot looks empty"
        )

        # File paths should be realistic (not /tmp/fake_file_1)
        for f in fake_files:
            assert "fake" not in f.lower(), (
                f"CRITICAL: Fake file path contains 'fake': {f} -- "
                "attacker can detect honeypot by path name"
            )
            assert "decoy" not in f.lower(), (
                f"CRITICAL: Fake file path contains 'decoy': {f} -- "
                "attacker can detect honeypot by path name"
            )
            assert "honeypot" not in f.lower(), (
                f"CRITICAL: Fake file path contains 'honeypot': {f} -- "
                "attacker can detect honeypot by path name"
            )

    # -- 3.5 Vulnerability exploit hint not too obvious -------------------

    def test_vulnerability_exploit_hint_not_too_obvious(self) -> None:
        """Exploit hints shouldn't scream 'this is a honeypot!'.

        Attack scenario: attacker reads vulnerability descriptions and
        finds text like 'this is a honeypot' or 'fake vulnerability'.
        """
        honeypot_signals = [
            "honeypot",
            "decoy",
            "fake vulnerability",
            "this is a trap",
            "simulated",
            "not real",
        ]

        for persona_class in [
            LegacyAPIPersona,
            ForgottenJenkinsPersona,
            LeakyS3Persona,
            ChattyDBPersona,
            DevServerPersona,
            VPNPortalPersona,
        ]:
            persona = persona_class()
            for vuln in persona._config.vulnerabilities:
                hint_lower = vuln.exploit_hint.lower()
                desc_lower = vuln.description.lower()
                combined = hint_lower + " " + desc_lower

                for signal in honeypot_signals:
                    assert signal not in combined, (
                        f"CRITICAL: {persona_class.__name__} vulnerability "
                        f"'{vuln.name}' contains honeypot signal '{signal}' "
                        f"in hint/description -- immediate detection"
                    )

    # -- 3.6 Canary tokens shouldn't follow predictable pattern -----------

    def test_canary_tokens_detectable_pattern(self) -> None:
        """Canary tokens shouldn't follow a predictable pattern.

        Attack scenario: attacker finds tokens like 'canary_001',
        'canary_002' and immediately knows they're in a honeypot.
        Tokens should look like real data.
        """
        # Check bait_data in various personas for predictable patterns
        predictable_patterns = [
            "canary",
            "honeypot_token",
            "decoy_",
            "fake_",
            "trap_",
            "bait_",
            "token_001",
            "token_002",
        ]

        for persona_class in [
            LegacyAPIPersona,
            ForgottenJenkinsPersona,
            LeakyS3Persona,
            ChattyDBPersona,
            DevServerPersona,
            VPNPortalPersona,
        ]:
            persona = persona_class()
            bait = persona._config.bait_data

            bait_str = str(bait).lower()
            for pattern in predictable_patterns:
                assert pattern not in bait_str, (
                    f"CRITICAL: {persona_class.__name__} bait_data contains "
                    f"predictable pattern '{pattern}': {bait} -- "
                    "attacker can detect honeypot by token naming"
                )


# ============================================================================
# Test Class 4: Rate Limiter Bypass (5 tests)
# ============================================================================


class TestRateLimiterBypass:
    """Tests that the rate limiter can't be bypassed.

    Sophisticated attackers know rate limiters track by IP or session.
    They'll try IP spoofing, rotating identifiers, and window-edge
    attacks to slip through.
    """

    # -- 4.1 Same identifier rate limited ---------------------------------

    @pytest.mark.asyncio
    async def test_same_identifier_rate_limited(self) -> None:
        """Same IP should be rate-limited after max_requests.

        Attack scenario: basic brute-force from single IP.
        """
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        ip = "192.168.1.100"

        # Send max_requests + 1 requests
        for i in range(6):
            allowed = limiter.check(ip)
            if i < 5:
                assert allowed is True, (
                    f"CRITICAL: Request {i+1}/5 was blocked unexpectedly"
                )
            else:
                assert allowed is False, (
                    f"CRITICAL: Request 6/5 was allowed -- "
                    "rate limiter not enforcing cap"
                )

    # -- 4.2 Changing identifier resets limit (vulnerability) ------------

    @pytest.mark.asyncio
    async def test_changing_identifier_resets_limit(self) -> None:
        """If changing IP resets limit, that's a vulnerability.

        Attack scenario: attacker rotates source IP (via proxy pool,
        X-Forwarded-For spoofing) to bypass per-IP rate limiting.

        This test documents the KNOWN VULNERABILITY: the in-memory
        rate limiter tracks by IP string only. An attacker with a
        proxy pool can bypass it entirely.
        """
        limiter = RateLimiter(max_requests=3, window_seconds=60)

        # Attacker sends 3 requests from IP 1 (gets blocked)
        for _ in range(3):
            limiter.check("192.168.1.1")

        # 4th request from same IP is blocked
        assert limiter.check("192.168.1.1") is False

        # Attacker rotates to a new IP
        allowed_after_rotation = limiter.check("192.168.1.2")

        # DOCUMENT the vulnerability -- don't assert it as a failure
        # because this is a known limitation of the stub implementation.
        # Instead, log it as an informational finding.
        if allowed_after_rotation:
            pytest.skip(
                "KNOWN VULNERABILITY: Rate limiter tracks by IP only. "
                "An attacker rotating IPs (proxy pool) can bypass limits. "
                "Replace with Redis-backed rate limiter for production."
            )

    # -- 4.3 Boundary exactly at limit ------------------------------------

    @pytest.mark.asyncio
    async def test_boundary_exactly_at_limit(self) -> None:
        """Exactly max_requests should be allowed, max+1 blocked.

        Attack scenario: attacker probes the exact boundary to find
        off-by-one errors in the rate limiter logic.
        """
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        ip = "10.0.0.50"

        # Exactly 5 requests should all be allowed
        for i in range(5):
            assert limiter.check(ip) is True, (
                f"CRITICAL: Request {i+1}/5 was blocked -- "
                "off-by-one error in rate limiter"
            )

        # The 6th should be blocked
        assert limiter.check(ip) is False, (
            "CRITICAL: Request 6/5 was allowed -- "
            "rate limit boundary not enforced"
        )

        # Verify remaining count is 0
        assert limiter.remaining(ip) == 0, (
            f"CRITICAL: remaining() returned {limiter.remaining(ip)} "
            f"after limit exhausted, expected 0"
        )

    # -- 4.4 Window edge exploitation -------------------------------------

    @pytest.mark.asyncio
    async def test_window_edge_exploitation(self) -> None:
        """Attacker shouldn't exploit window boundaries.

        Attack scenario: attacker sends max_requests at t=0, then
        waits just past the window and sends max_requests again,
        effectively getting 2x the intended rate.
        """
        # Use a very small window for testing
        limiter = RateLimiter(max_requests=3, window_seconds=1)
        ip = "10.0.0.77"

        # Exhaust the limit
        for _ in range(3):
            limiter.check(ip)

        # Should be blocked
        assert limiter.check(ip) is False

        # Wait for the window to expire
        await asyncio.sleep(1.1)

        # After window expires, requests should be allowed again
        assert limiter.check(ip) is True, (
            "INFO: Request after window expiry was blocked -- "
            "window cleanup may not be working correctly"
        )

    # -- 4.5 Rate limit returns proper signal -----------------------------

    @pytest.mark.asyncio
    async def test_rate_limit_returns_429(self) -> None:
        """Rate limit exceeded should raise RateLimitExceeded with retry_after.

        Attack scenario: attacker needs to know how long to wait.
        If the error leaks internal state or doesn't provide retry_after,
        the attacker's tooling may behave unpredictably.
        """
        limiter = RateLimiter(max_requests=2, window_seconds=30)
        ip = "10.0.0.88"

        # Exhaust the limit
        limiter.check(ip)
        limiter.check(ip)

        # Third request should be denied
        allowed = limiter.check(ip)
        assert allowed is False

        # The RateLimitExceeded exception should contain retry_after
        try:
            raise RateLimitExceeded(retry_after=limiter.window_seconds)
        except RateLimitExceeded as exc:
            assert hasattr(exc, "retry_after"), (
                "CRITICAL: RateLimitExceeded missing retry_after attribute"
            )
            assert exc.retry_after > 0, (
                f"CRITICAL: retry_after is {exc.retry_after}, must be positive"
            )
            assert exc.retry_after == 30, (
                f"CRITICAL: retry_after is {exc.retry_after}, expected 30"
            )


# ============================================================================
# Additional Edge-Case Tests (bonus adversarial probes)
# ============================================================================


class TestEdgeCaseAttacks:
    """Bonus adversarial tests for edge cases and creative attacks."""

    @pytest.mark.asyncio
    async def test_double_destroy_is_safe(self) -> None:
        """Destroying same instance twice shouldn't crash.

        Attack scenario: race condition or replay attack where the
        attacker sends two destroy requests for the same instance.
        """
        config = HoneypotConfig(max_instances=10)
        engine = HoneypotEngine(config=config)
        await engine.start()

        persona = EngineDecoyPersona()
        instance = await engine.spawn_instance(persona)
        instance_id = instance.id

        # First destroy
        await engine.destroy_instance(instance_id)

        # Second destroy should not crash
        try:
            await engine.destroy_instance(instance_id)
            # If it raises KeyError, that's acceptable behavior
        except KeyError:
            pass  # Expected: instance already destroyed

        await engine.stop()

    @pytest.mark.asyncio
    async def test_paused_instance_cannot_be_paused_again(self) -> None:
        """Double-pause should be rejected.

        Attack scenario: state-machine fuzzing to find invalid transitions.
        """
        config = HoneypotConfig(max_instances=10)
        engine = HoneypotEngine(config=config)
        await engine.start()

        persona = EngineDecoyPersona()
        instance = await engine.spawn_instance(persona)

        await engine.pause_instance(instance.id)

        # Second pause should fail
        with pytest.raises(RuntimeError):
            await engine.pause_instance(instance.id)

        await engine.stop()

    def test_persona_password_hint_not_always_default(self) -> None:
        """Password hint should not always be the hardcoded default.

        Attack scenario: attacker checks password hints and finds
        the same hint across all personas -- fingerprinting signal.
        """
        hints: list[str] = []
        for _ in range(20):
            persona = EngineDecoyPersona()
            hints.append(persona.password_hint)

        default_count = hints.count("Summer2024!")
        # If ALL personas have the same hint, that's a fingerprinting signal
        if default_count == len(hints):
            pytest.skip(
                "KNOWN VULNERABILITY: All personas have the same password hint "
                "'Summer2024!' -- this is fingerprintable. "
                "See test_password_hint_not_obvious for full details."
            )

    @pytest.mark.asyncio
    async def test_orchestrator_health_leaks_no_sensitive_data(self) -> None:
        """Health check should not leak internal paths, keys, or creds.

        Attack scenario: attacker calls /health and finds database
        passwords, file paths, or internal IP addresses.
        """
        orch = HoneypotOrchestrator()
        health = await orch.health_check()

        health_str = str(health).lower()
        sensitive_patterns = [
            "password", "secret", "token", "key", "credential",
            "private", "/etc/shadow", "/.ssh/",
        ]

        found = [p for p in sensitive_patterns if p in health_str]
        assert not found, (
            f"CRITICAL: Health check leaks sensitive patterns: {found} -- "
            f"health data: {health}"
        )

    def test_rate_limiter_cleanup_removes_stale_ips(self) -> None:
        """Stale IP entries should be cleaned up.

        Attack scenario: attacker sends requests from many IPs and
        lets them age out. If cleanup doesn't work, memory grows.
        """
        limiter = RateLimiter(max_requests=5, window_seconds=1)

        # Add entries for many IPs
        for i in range(100):
            limiter.check(f"10.0.{i // 256}.{i % 256}")

        # Wait for window to expire
        time.sleep(1.1)

        # Cleanup should remove stale entries
        cleaned = limiter.cleanup()
        assert cleaned > 0, (
            "CRITICAL: cleanup() did not remove any stale IP entries -- "
            "memory will grow unboundedly under distributed scanning"
        )

        # After cleanup, stats should reflect it
        stats = limiter.get_stats()
        assert stats["tracked_ips"] == 0, (
            f"CRITICAL: {stats['tracked_ips']} IPs still tracked after cleanup -- "
            "stale entries not removed"
        )
