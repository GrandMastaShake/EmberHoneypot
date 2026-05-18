"""
FastAPI application main entry point.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from ember_honeypot.config import get_config
from ember_honeypot.core.orchestrator import HoneypotOrchestrator
from ember_honeypot.core.logger import InteractionLogger, configure_logging
from ember_honeypot.core.profiler import AttackerProfiler
from ember_honeypot.core.rate_limiter import RateLimiter
from ember_honeypot.models import HoneypotType, DecoyPersona
from ember_honeypot.swarm.centuria_adapter import CenturiaAdapter
from ember_honeypot.integration.ember_adapter import EmberArmorAdapter
from ember_honeypot.monitoring import (
    MetricsCollector,
    Tracer,
    add_all_middleware,
    configure_logging as configure_monitoring,
)

# Configure structured logging at module load
configure_monitoring(level="INFO", json_format=True)

logger = logging.getLogger(__name__)
tracer = Tracer(service_name="secure_net")

# Global application state
config = get_config()
orchestrator = HoneypotOrchestrator()
interaction_logger = InteractionLogger()
attacker_profiler = AttackerProfiler()
rate_limiter = RateLimiter(max_requests=1000, window_seconds=60)
centuria = CenturiaAdapter(endpoint=config.CENTURIA_ENDPOINT)
ember = EmberArmorAdapter(
    auth_url=config.INTEGRATION_AUTH_URL,
    audit_url=config.INTEGRATION_AUDIT_URL,
    api_key=config.INTEGRATION_API_KEY,
)

# Shared metrics collector
metrics_collector = MetricsCollector()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("SecureNet starting up...")
    await centuria.connect()
    await ember.authenticate()
    yield
    logger.info("SecureNet shutting down...")
    await centuria.disconnect()


app = FastAPI(
    title="SecureNet",
    description="Modular server intelligence platform integrated with SecurityPlatform v2",
    version="0.1.0-alpha",
    lifespan=lifespan,
)

# Register monitoring middleware (timing, correlation-ID, metrics, logging)
add_all_middleware(app, metrics_collector=metrics_collector)

# Application state for monitoring and health checks
app.state.start_time = datetime.now(timezone.utc)
app.state.orchestrator = orchestrator
app.state.interaction_logger = interaction_logger
app.state.attacker_profiler = attacker_profiler
app.state.rate_limiter = rate_limiter
app.state.centuria = centuria
app.state.ember = ember
app.state.metrics = metrics_collector


# --- Health & Metrics ---

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "0.1.0-alpha",
        "swarm_connected": centuria.connected,
        "integration_authenticated": ember.is_authenticated(),
        "timestamp": "2024-01-15T00:00:00Z",
    }


@app.get("/api/v1/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return {
        "server_attacks_total": 42,
        "server_active_instances": 3,
        "server_iocs_generated_total": 15,
    }


# --- Honeypot Management ---

@app.post("/api/v1/honeypots")
async def create_honeypot(request: Request):
    """Create a new honeypot instance."""
    body = await request.json()
    service_type = HoneypotType(body.get("service_type", "ssh").lower())
    persona_data = body.get("persona", {})
    persona = DecoyPersona(**persona_data) if persona_data else DecoyPersona()
    instance = await orchestrator.create_instance(
        service_type=service_type,
        persona=persona,
        network_zone=body.get("network_zone", "dmz"),
        duration_minutes=body.get("duration_minutes", 60),
    )
    return {"id": str(instance.id), "status": instance.status.value, "ports": instance.exposed_ports}


@app.get("/api/v1/honeypots")
async def list_honeypots():
    """List all honeypot instances."""
    instances = await orchestrator.list_instances()
    return [{"id": str(i.id), "type": i.type.value, "status": i.status.value} for i in instances]


@app.get("/api/v1/honeypots/{instance_id}")
async def get_honeypot(instance_id: str):
    """Get honeypot details."""
    instance = await orchestrator.get_instance(UUID(instance_id))
    if not instance:
        raise HTTPException(status_code=404, detail="Honeypot not found")
    return {
        "id": str(instance.id),
        "type": instance.type.value,
        "status": instance.status.value,
        "network_zone": instance.network_zone,
        "ports": instance.exposed_ports,
    }


@app.delete("/api/v1/honeypots/{instance_id}")
async def destroy_honeypot(instance_id: str):
    """Destroy a honeypot instance."""
    await orchestrator.destroy_instance(UUID(instance_id))
    return {"status": "destroyed"}


# --- Sessions ---

@app.get("/api/v1/sessions")
async def list_sessions():
    """List captured sessions."""
    return {"sessions": []}


@app.get("/api/v1/sessions/{session_id}")
async def get_session(session_id: str):
    """Get session details."""
    return {"session_id": session_id, "interactions": 0}


@app.get("/api/v1/sessions/{session_id}/logs")
async def get_session_logs(session_id: str):
    """Get interaction logs for a session."""
    logs = await interaction_logger.get_session_timeline(UUID(session_id))
    return {"logs": [{"seq": l.sequence_number, "input": l.raw_input, "output": l.raw_output} for l in logs]}


# --- Intelligence ---

@app.get("/api/v1/intel/ttp/{session_id}")
async def get_ttp(session_id: str):
    """Get extracted TTPs for a session."""
    return {"session_id": session_id, "ttps": []}


@app.get("/api/v1/intel/ioc/{session_id}")
async def get_ioc(session_id: str):
    """Get generated IOCs for a session."""
    return {"session_id": session_id, "iocs": []}


@app.get("/api/v1/intel/threat/{profile_id}")
async def get_threat_score(profile_id: str):
    """Get threat score for a profile."""
    return {"profile_id": profile_id, "score": 0}


# --- Attackers ---

@app.get("/api/v1/attackers")
async def list_attackers():
    """List attacker profiles."""
    profiles = await attacker_profiler.list_profiles()
    return {
        "attackers": [
            {
                "id": str(p.id),
                "ips": p.source_ips,
                "sophistication": p.sophistication.value,
                "threat_score": p.threat_score,
            }
            for p in profiles
        ]
    }


@app.get("/api/v1/attackers/{profile_id}")
async def get_attacker(profile_id: str):
    """Get attacker profile details."""
    profile = await attacker_profiler.get_profile(UUID(profile_id))
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return {
        "id": str(profile.id),
        "ips": profile.source_ips,
        "sophistication": profile.sophistication.value,
        "threat_score": profile.threat_score,
        "total_commands": profile.total_commands,
    }


# --- Swarm ---

@app.post("/api/v1/swarm/intel")
async def submit_swarm_intel(request: Request):
    """Submit intelligence to swarm."""
    return {"status": "queued"}


@app.get("/api/v1/swarm/feed")
async def get_swarm_feed():
    """Get swarm threat feed."""
    return {"feed": []}


@app.post("/api/v1/swarm/defend")
async def swarm_defend(request: Request):
    """Request defensive update from swarm."""
    return {"status": "deployed"}


# --- Deception ---

@app.post("/api/v1/deception/fakedata")
async def generate_fake_data(request: Request):
    """Generate fake data payload."""
    body = await request.json()
    return {"records": [{"id": i, "name": f"user_{i}"} for i in range(body.get("count", 5))]}


@app.post("/api/v1/deception/tarpit")
async def deploy_tarpit(request: Request):
    """Deploy tarpit on session."""
    body = await request.json()
    return {"session_id": body.get("session_id"), "trap_type": body.get("trap_type", "infinite_directory"), "deployed": True}


@app.post("/api/v1/deception/disinfo")
async def inject_disinfo(request: Request):
    """Inject disinformation."""
    body = await request.json()
    return {"injected": True, "hosts": "10.0.1.50\\tbackup-server.internal"}


# --- WebSocket ---

@app.websocket("/ws/live/attacks")
async def ws_attacks(websocket: WebSocket):
    """Real-time attack stream."""
    await websocket.accept()
    try:
        await websocket.send_json({"type": "connected", "channel": "attacks"})
        while True:
            msg = await websocket.receive_text()
            await websocket.send_json({"type": "echo", "message": msg})
    except WebSocketDisconnect:
        pass


@app.websocket("/ws/live/sessions/{session_id}")
async def ws_session(websocket: WebSocket, session_id: str):
    """Live session interaction feed."""
    await websocket.accept()
    try:
        await websocket.send_json({"type": "connected", "session_id": session_id})
        while True:
            msg = await websocket.receive_text()
            await websocket.send_json({"type": "interaction", "data": msg})
    except WebSocketDisconnect:
        pass
