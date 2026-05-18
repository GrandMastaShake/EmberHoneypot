"""
test_api.py -- Tests for the API layer.

Covers:
- All REST endpoints with httpx AsyncClient
- WebSocket connection and message flow
- Error handling
"""

from __future__ import annotations

import pytest
from uuid import uuid4


# ============================================================================
# Health & Metrics Endpoints
# ============================================================================

class TestHealthEndpoints:
    """Test health check and metrics endpoints."""

    @pytest.mark.asyncio
    async def test_health_check(self, async_client) -> None:
        """Test /api/v1/health returns healthy status."""
        response = await async_client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data

    @pytest.mark.asyncio
    async def test_metrics_endpoint(self, async_client) -> None:
        """Test /api/v1/metrics returns metrics."""
        response = await async_client.get("/api/v1/metrics")
        assert response.status_code == 200
        data = response.json()
        assert "server_attacks_total" in data


# ============================================================================
# Honeypot Management Endpoints
# ============================================================================

class TestHoneypotEndpoints:
    """Test honeypot CRUD endpoints."""

    @pytest.mark.asyncio
    async def test_create_honeypot(self, async_client) -> None:
        """Test POST /api/v1/honeypots creates a honeypot."""
        payload = {
            "service_type": "SSH",
            "persona": {
                "role": "developer",
                "name": "Test Dev",
                "username": "tdev",
            },
            "network_zone": "dmz",
            "duration_minutes": 60,
        }
        response = await async_client.post("/api/v1/honeypots", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
        assert data["status"] == "active"
        assert "ports" in data

    @pytest.mark.asyncio
    async def test_create_honeypot_http(self, async_client) -> None:
        """Test creating an HTTP honeypot."""
        payload = {
            "service_type": "HTTP",
            "persona": {"role": "admin", "name": "Admin", "username": "admin"},
        }
        response = await async_client.post("/api/v1/honeypots", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "active"

    @pytest.mark.asyncio
    async def test_list_honeypots(self, async_client) -> None:
        """Test GET /api/v1/honeypots returns list."""
        response = await async_client.get("/api/v1/honeypots")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_get_honeypot(self, async_client) -> None:
        """Test GET /api/v1/honeypots/{id}."""
        # Create first
        payload = {
            "service_type": "SSH",
            "persona": {"role": "developer", "name": "Dev", "username": "dev"},
        }
        create_resp = await async_client.post("/api/v1/honeypots", json=payload)
        hp_id = create_resp.json()["id"]

        response = await async_client.get(f"/api/v1/honeypots/{hp_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == hp_id
        assert "type" in data
        assert "status" in data

    @pytest.mark.asyncio
    async def test_get_honeypot_not_found(self, async_client) -> None:
        """Test GET /api/v1/honeypots/{id} returns 404 for unknown."""
        response = await async_client.get(f"/api/v1/honeypots/{uuid4()}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_destroy_honeypot(self, async_client) -> None:
        """Test DELETE /api/v1/honeypots/{id}."""
        payload = {
            "service_type": "SSH",
            "persona": {"role": "developer", "name": "Dev", "username": "dev"},
        }
        create_resp = await async_client.post("/api/v1/honeypots", json=payload)
        hp_id = create_resp.json()["id"]

        response = await async_client.delete(f"/api/v1/honeypots/{hp_id}")
        assert response.status_code == 200
        assert response.json()["status"] == "destroyed"


# ============================================================================
# Session Endpoints
# ============================================================================

class TestSessionEndpoints:
    """Test session endpoints."""

    @pytest.mark.asyncio
    async def test_list_sessions(self, async_client) -> None:
        """Test GET /api/v1/sessions."""
        response = await async_client.get("/api/v1/sessions")
        assert response.status_code == 200
        data = response.json()
        assert "sessions" in data

    @pytest.mark.asyncio
    async def test_get_session(self, async_client) -> None:
        """Test GET /api/v1/sessions/{id}."""
        session_id = str(uuid4())
        response = await async_client.get(f"/api/v1/sessions/{session_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["session_id"] == session_id

    @pytest.mark.asyncio
    async def test_get_session_logs(self, async_client) -> None:
        """Test GET /api/v1/sessions/{id}/logs."""
        session_id = str(uuid4())
        response = await async_client.get(f"/api/v1/sessions/{session_id}/logs")
        assert response.status_code == 200
        data = response.json()
        assert "logs" in data


# ============================================================================
# Intelligence Endpoints
# ============================================================================

class TestIntelEndpoints:
    """Test intelligence endpoints."""

    @pytest.mark.asyncio
    async def test_get_ttp(self, async_client) -> None:
        """Test GET /api/v1/intel/ttp/{session_id}."""
        session_id = str(uuid4())
        response = await async_client.get(f"/api/v1/intel/ttp/{session_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["session_id"] == session_id

    @pytest.mark.asyncio
    async def test_get_ioc(self, async_client) -> None:
        """Test GET /api/v1/intel/ioc/{session_id}."""
        session_id = str(uuid4())
        response = await async_client.get(f"/api/v1/intel/ioc/{session_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["session_id"] == session_id

    @pytest.mark.asyncio
    async def test_get_threat_score(self, async_client) -> None:
        """Test GET /api/v1/intel/threat/{profile_id}."""
        profile_id = str(uuid4())
        response = await async_client.get(f"/api/v1/intel/threat/{profile_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["profile_id"] == profile_id


# ============================================================================
# Attacker Endpoints
# ============================================================================

class TestAttackerEndpoints:
    """Test attacker profile endpoints."""

    @pytest.mark.asyncio
    async def test_list_attackers(self, async_client) -> None:
        """Test GET /api/v1/attackers."""
        response = await async_client.get("/api/v1/attackers")
        assert response.status_code == 200
        data = response.json()
        assert "attackers" in data

    @pytest.mark.asyncio
    async def test_get_attacker_not_found(self, async_client) -> None:
        """Test GET /api/v1/attackers/{id} returns 404."""
        response = await async_client.get(f"/api/v1/attackers/{uuid4()}")
        assert response.status_code == 404


# ============================================================================
# Swarm Endpoints
# ============================================================================

class TestSwarmEndpoints:
    """Test swarm integration endpoints."""

    @pytest.mark.asyncio
    async def test_submit_swarm_intel(self, async_client) -> None:
        """Test POST /api/v1/swarm/intel."""
        payload = {"attacker_ip": "10.0.0.1", "threat_score": 75}
        response = await async_client.post("/api/v1/swarm/intel", json=payload)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_get_swarm_feed(self, async_client) -> None:
        """Test GET /api/v1/swarm/feed."""
        response = await async_client.get("/api/v1/swarm/feed")
        assert response.status_code == 200
        assert "feed" in response.json()

    @pytest.mark.asyncio
    async def test_swarm_defend(self, async_client) -> None:
        """Test POST /api/v1/swarm/defend."""
        payload = {"threat_level": "high"}
        response = await async_client.post("/api/v1/swarm/defend", json=payload)
        assert response.status_code == 200


# ============================================================================
# Deception Endpoints
# ============================================================================

class TestDeceptionEndpoints:
    """Test deception control endpoints."""

    @pytest.mark.asyncio
    async def test_generate_fake_data(self, async_client) -> None:
        """Test POST /api/v1/deception/fakedata."""
        payload = {"table": "users", "count": 5}
        response = await async_client.post("/api/v1/deception/fakedata", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "records" in data

    @pytest.mark.asyncio
    async def test_deploy_tarpit(self, async_client) -> None:
        """Test POST /api/v1/deception/tarpit."""
        payload = {"session_id": str(uuid4()), "trap_type": "infinite_directory"}
        response = await async_client.post("/api/v1/deception/tarpit", json=payload)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_inject_disinfo(self, async_client) -> None:
        """Test POST /api/v1/deception/disinfo."""
        payload = {"session_id": str(uuid4())}
        response = await async_client.post("/api/v1/deception/disinfo", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["injected"] is True


# ============================================================================
# WebSocket Endpoints -- tested via direct app testing
# ============================================================================

class TestWebSocketEndpoints:
    """Test WebSocket endpoints."""

    @pytest.mark.asyncio
    async def test_ws_attacks_connect(self) -> None:
        """Test WebSocket /ws/live/attacks connection via TestClient."""
        from fastapi.testclient import TestClient
        from ember_honeypot.api.main import app

        client = TestClient(app)
        with client.websocket_connect("/ws/live/attacks") as ws:
            msg = ws.receive_json()
            assert msg["type"] == "connected"
            assert msg["channel"] == "attacks"
            ws.send_text("test")
            echo = ws.receive_json()
            assert echo["type"] == "echo"

    @pytest.mark.asyncio
    async def test_ws_session_connect(self) -> None:
        """Test WebSocket /ws/live/sessions/{id} connection."""
        from fastapi.testclient import TestClient
        from ember_honeypot.api.main import app

        session_id = str(uuid4())
        client = TestClient(app)
        with client.websocket_connect(f"/ws/live/sessions/{session_id}") as ws:
            msg = ws.receive_json()
            assert msg["type"] == "connected"
            assert msg["session_id"] == session_id
