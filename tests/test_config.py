"""
test_config.py -- Tests for the fail-closed configuration.

Covers:
- Config loading and validation
- Fail-closed behavior
- Ember pattern compliance
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from pydantic import ValidationError

from ember_honeypot.config import AppConfig as HoneypotConfig, get_config


class TestHoneypotConfig:
    """Test configuration system."""

    def test_default_config(self) -> None:
        """Test config loads with defaults."""
        config = HoneypotConfig()
        assert config.DATABASE_URL.startswith("postgresql://")
        assert config.REDIS_URL.startswith("redis://")
        assert config.API_PORT == 8080
        assert config.LOG_LEVEL in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

    def test_fail_closed_property(self) -> None:
        """Test fail-closed property."""
        config = HoneypotConfig()
        assert config.is_fail_closed == config.FAIL_CLOSED

    def test_swarm_active_without_key(self) -> None:
        """Test swarm not active without API key."""
        config = HoneypotConfig(CENTURIA_API_KEY=None, SWARM_ENABLED=True)
        assert config.swarm_active is False

    def test_swarm_active_with_key(self) -> None:
        """Test swarm active with API key."""
        config = HoneypotConfig(CENTURIA_API_KEY="test-key", SWARM_ENABLED=True)
        assert config.swarm_active is True

    def test_ember_configured_with_key(self) -> None:
        """Test Ember configured with API key."""
        config = HoneypotConfig(INTEGRATION_API_KEY="test-key")
        assert config.ember_configured is True

    def test_ember_configured_without_key(self) -> None:
        """Test Ember not configured without API key."""
        config = HoneypotConfig(INTEGRATION_API_KEY=None)
        assert config.ember_configured is False

    def test_log_level_validation(self) -> None:
        """Test log level validation."""
        config = HoneypotConfig(LOG_LEVEL="debug")
        assert config.LOG_LEVEL == "DEBUG"

        config = HoneypotConfig(LOG_LEVEL="INFO")
        assert config.LOG_LEVEL == "INFO"

        config = HoneypotConfig(LOG_LEVEL="ERROR")
        assert config.LOG_LEVEL == "ERROR"

    def test_invalid_log_level(self) -> None:
        """Test invalid log level is rejected."""
        with pytest.raises(ValidationError):
            HoneypotConfig(LOG_LEVEL="invalid_level")

    def test_database_url_validation(self) -> None:
        """Test database URL scheme validation."""
        with pytest.raises(ValidationError):
            HoneypotConfig(DATABASE_URL="sqlite:///test.db")

    def test_database_url_valid(self) -> None:
        """Test valid database URL."""
        config = HoneypotConfig(DATABASE_URL="postgresql://user:pass@host:5432/db")
        assert config.DATABASE_URL == "postgresql://user:pass@host:5432/db"

    def test_threat_score_bounds(self) -> None:
        """Test threat score field bounds."""
        from ember_honeypot.models import ThreatScore
        score = ThreatScore(overall=0.50, sophistication=0.50, persistence=0.50, stealth=0.50, aggressiveness=0.50, adaptability=0.50)
        assert 0 <= score.overall <= 100

    def test_config_singleton(self) -> None:
        """Test config singleton returns same type."""
        config1 = get_config()
        config2 = get_config()
        assert type(config1) == type(config2)
        assert config1.API_PORT == config2.API_PORT

    def test_feature_flags(self) -> None:
        """Test feature flag defaults."""
        config = HoneypotConfig()
        assert isinstance(config.CANARY_ENABLED, bool)
        assert isinstance(config.TARPIT_ENABLED, bool)
        assert isinstance(config.ADAPTIVE_DEFENSE, bool)

    def test_max_limits(self) -> None:
        """Test maximum session/honeypot limits."""
        config = HoneypotConfig(MAX_SESSIONS=500, MAX_HONEYPOTS=25)
        assert config.MAX_SESSIONS == 500
        assert config.MAX_HONEYPOTS == 25
