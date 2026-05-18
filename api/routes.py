"""
FastAPI REST routes for SecureNet management, intelligence, and monitoring.

Track 2a: SecureNet Core + API Layer
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Any


from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from ember_honeypot.api.models import (
    ApiHoneypotType,
    ApiInstanceStatus,
    ApiInteractionType,
    ApiSophisticationLevel,
    AttackTimelineEvent,
    AttackTimelineResponse,
    AttackerListResponse,
    AttackerProfileResponse,
    ComponentHealth,
    DecoyPersonaResponse,
    ErrorResponse,
    HealthResponse,
    HoneypotListResponse,
    HoneypotResponse,
    InstanceMetricsResponse,
    InteractionFilterRequest,
    InteractionListResponse,
    InteractionResponse,
    MessageResponse,
    PersonaCreateRequest,
    TTPResponse,
    ToolDetectionResponse,
)
from ember_honeypot.monitoring.health import HealthChecker
from ember_honeypot.monitoring.metrics import MetricsCollector

logger = logging.getLogger(__name__)

# In-memory metrics collector for the routes module
_metrics_collector = MetricsCollector()

# ── Router Factory ───────────────────────────────────────────────────────


def create_api_router() -> APIRouter:
    """Create and configure the SecureNet API router.

    Returns:
        Configured APIRouter with all server endpoints.
    """
    router = APIRouter(prefix="/api/v1")

    # ── Health ──────────────────────────────────────────────────────────

    @router.get(
        "/health",
        response_model=HealthResponse,
        summary="Health check with component diagnostics",
        description=(
            "Returns aggregated health status with per-component checks "
            "for orchestrator, engine, rate limiter, attacker profiler, and disk."
        ),
        tags=["health"],
    )
    async def health_check(request: Request) -> HealthResponse:
        engine = request.app.state.engine
        orchestrator = getattr(request.app.state, "orchestrator", None)
        rate_limiter = getattr(request.app.state, "rate_limiter", None)
        profiler = getattr(request.app.state, "attacker_profiler", None)

        uptime = 0.0
        if hasattr(request.app.state, "start_time"):
            uptime = (
                datetime.now(timezone.utc) - request.app.state.start_time
            ).total_seconds()

        # Build HealthChecker and run component checks
        checker = HealthChecker(
            version="0.1.0",
            start_time=getattr(request.app.state, "start_time", None),
            orchestrator=orchestrator,
            engine=engine,
            rate_limiter=rate_limiter,
            attacker_profiler=profiler,
        )
        status = await checker.check(depth="shallow")

        # Convert monitoring ComponentHealth to API ComponentHealth
        components = [
            ComponentHealth(
                name=c.name,
                status=c.status,
                response_time_ms=c.response_time_ms,
                detail=c.detail,
                metadata=c.metadata,
            )
            for c in status.components
        ]

        return HealthResponse(
            status=status.overall,
            version=status.version,
            uptime_seconds=round(status.uptime_seconds, 2),
            components=components,
            timestamp=status.timestamp.isoformat(),
        )

    # ── Honeypot Management ─────────────────────────────────────────────

    @router.get(
        "/honeypots",
        response_model=HoneypotListResponse,
        summary="List all server instances",
        description="Returns all server instances with optional status filter.",
        tags=["servers"],
    )
    async def list_honeypots(
        request: Request,
        status: ApiInstanceStatus | None = None,
    ) -> HoneypotListResponse:
        engine = request.app.state.engine

        # Convert API enum to core enum
        core_status = None
        if status is not None:
            from ember_honeypot.core.engine import InstanceStatus

            core_status = InstanceStatus(status.value)

        instances = await engine.list_instances(status=core_status)

        active_count = sum(
            1 for i in instances if i.status.value == "active"
        )

        return HoneypotListResponse(
            instances=[_instance_to_response(i) for i in instances],
            total=len(instances),
            active_count=active_count,
        )

    @router.post(
        "/honeypots",
        response_model=HoneypotResponse,
        status_code=201,
        summary="Spawn a new server instance",
        description="Create and start a new server with the given persona configuration.",
        tags=["servers"],
    )
    async def spawn_honeypot(
        request: Request,
        body: PersonaCreateRequest,
        service_type: ApiHoneypotType = ApiHoneypotType.SSH,
        network_zone: str = "server-net",
    ) -> HoneypotResponse:
        engine = request.app.state.engine

        if not engine.is_running:
            raise HTTPException(
                status_code=503,
                detail="Engine is not running",
            )

        # Convert request to core persona model
        from ember_honeypot.core.engine import DecoyPersona, HoneypotType

        persona = DecoyPersona(
            role=body.role,
            name=body.name,
            username=body.username,
            password_hint=body.password_hint,
            ssh_keys=body.ssh_keys,
            file_preferences=body.file_preferences,
            typical_commands=body.typical_commands,
            environment_vars=body.environment_vars,
            fake_projects=body.fake_projects,
        )

        core_type = HoneypotType(service_type.value)

        try:
            instance = await engine.spawn_instance(
                persona=persona,
                service_type=core_type,
                network_zone=network_zone,
            )
        except RuntimeError as exc:
            logger.warning("spawn_server failed: %s", exc)
            raise HTTPException(status_code=409, detail="Conflict: engine state prevents spawning") from exc

        # Emit metric
        if hasattr(request.app.state, "metrics"):
            request.app.state.metrics["active_honeypots"].inc()

        return _instance_to_response(instance)

    @router.get(
        "/honeypots/{instance_id}",
        response_model=HoneypotResponse,
        summary="Get server instance details",
        description="Returns details for a specific server instance.",
        tags=["servers"],
    )
    async def get_honeypot(
        request: Request,
        instance_id: str,
    ) -> HoneypotResponse:
        engine = request.app.state.engine
        instance = await engine.get_instance(instance_id)
        if instance is None:
            raise HTTPException(
                status_code=404,
                detail=f"Server instance '{instance_id}' not found",
            )
        return _instance_to_response(instance)

    @router.delete(
        "/honeypots/{instance_id}",
        response_model=MessageResponse,
        summary="Destroy a server instance",
        description="Gracefully tear down a server instance.",
        tags=["servers"],
    )
    async def destroy_honeypot(
        request: Request,
        instance_id: str,
    ) -> MessageResponse:
        engine = request.app.state.engine

        try:
            await engine.destroy_instance(instance_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=404,
                detail=f"Server instance '{instance_id}' not found",
            ) from exc

        return MessageResponse(
            message=f"Instance '{instance_id}' destroyed successfully",
            instance_id=instance_id,
        )

    @router.post(
        "/honeypots/{instance_id}/pause",
        response_model=HoneypotResponse,
        summary="Pause a server instance",
        description="Pause a running instance (stop accepting connections).",
        tags=["servers"],
    )
    async def pause_honeypot(
        request: Request,
        instance_id: str,
    ) -> HoneypotResponse:
        engine = request.app.state.engine

        try:
            instance = await engine.pause_instance(instance_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=404,
                detail=f"Server instance '{instance_id}' not found",
            ) from exc
        except RuntimeError as exc:
            logger.warning("pause_server failed: %s", exc)
            raise HTTPException(status_code=409, detail="Conflict: cannot pause server in current state") from exc

        return _instance_to_response(instance)

    @router.post(
        "/honeypots/{instance_id}/resume",
        response_model=HoneypotResponse,
        summary="Resume a paused server instance",
        description="Resume a previously paused instance.",
        tags=["servers"],
    )
    async def resume_honeypot(
        request: Request,
        instance_id: str,
    ) -> HoneypotResponse:
        engine = request.app.state.engine

        try:
            instance = await engine.resume_instance(instance_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=404,
                detail=f"Server instance '{instance_id}' not found",
            ) from exc
        except RuntimeError as exc:
            logger.warning("resume_server failed: %s", exc)
            raise HTTPException(status_code=409, detail="Conflict: cannot resume server in current state") from exc

        return _instance_to_response(instance)

    # ── Interactions ────────────────────────────────────────────────────

    @router.get(
        "/interactions",
        response_model=InteractionListResponse,
        summary="List interaction logs",
        description="Query interaction logs with optional filters.",
        tags=["interactions"],
    )
    async def list_interactions(
        request: Request,
        attacker_ip: str | None = None,
        protocol: str | None = None,
        honeypot_id: str | None = None,
        interaction_type: ApiInteractionType | None = None,
        limit: int = Query(default=100, ge=1, le=10000),
        offset: int = Query(default=0, ge=0),
    ) -> InteractionListResponse:
        interaction_logger = request.app.state.interaction_logger

        if interaction_logger is None:
            return InteractionListResponse(
                interactions=[],
                total=0,
                limit=limit,
                offset=offset,
            )

        # Convert API enum to core enum
        core_type = None
        if interaction_type is not None:
            from ember_honeypot.core.interaction_logger import InteractionType

            core_type = InteractionType(interaction_type.value)

        interactions = interaction_logger.get_interactions(
            attacker_ip=attacker_ip,
            protocol=protocol,
            honeypot_id=honeypot_id,
            interaction_type=core_type,
            limit=limit,
            offset=offset,
        )

        total = interaction_logger.get_interaction_count(
            attacker_ip=attacker_ip,
            honeypot_id=honeypot_id,
        )

        return InteractionListResponse(
            interactions=[
                InteractionResponse(
                    id=i.id,
                    session_id=i.session_id,
                    honeypot_id=i.honeypot_id,
                    timestamp=i.timestamp,
                    attacker_ip=i.attacker_ip,
                    protocol=i.protocol,
                    interaction_type=ApiInteractionType(i.interaction_type.value),
                    payload=i.payload,
                    response_preview=i.response[:200] if i.response else "",
                    parsed_command=i.parsed_command,
                    user_context=i.user_context,
                )
                for i in interactions
            ],
            total=total,
            limit=limit,
            offset=offset,
        )

    @router.get(
        "/interactions/export",
        response_model=str,
        summary="Export interaction logs",
        description="Export all interaction logs in JSON or CSV format.",
        tags=["interactions"],
    )
    async def export_interactions(
        request: Request,
        fmt: str = Query(default="json", pattern="^(json|csv)$"),
    ) -> str:
        interaction_logger = request.app.state.interaction_logger

        if interaction_logger is None:
            raise HTTPException(
                status_code=503,
                detail="Interaction logger not available",
            )

        try:
            return interaction_logger.export_logs(fmt=fmt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid export format requested") from None

    # ── Attackers ───────────────────────────────────────────────────────

    @router.get(
        "/attackers",
        response_model=AttackerListResponse,
        summary="List attacker profiles",
        description="Returns all attacker profiles with threat scoring.",
        tags=["attackers"],
    )
    async def list_attackers(request: Request) -> AttackerListResponse:
        profiler = request.app.state.attacker_profiler

        if profiler is None:
            return AttackerListResponse(attackers=[], total=0)

        profiles = await profiler.get_all_profiles()

        # Build profiles for all unique IPs seen in logs
        interaction_logger = request.app.state.interaction_logger
        if interaction_logger is not None:
            unique_ips = interaction_logger.get_unique_attackers()
            for ip in unique_ips:
                existing = profiler.get_profile(ip)
                if existing is None:
                    try:
                        await profiler.profile_attacker(ip)
                    except Exception:
                        logger.warning("Failed to profile attacker %s", ip)

            profiles = await profiler.get_all_profiles()

        return AttackerListResponse(
            attackers=[_profile_to_response(p) for p in profiles],
            total=len(profiles),
        )

    @router.get(
        "/attackers/{attacker_ip}",
        response_model=AttackerProfileResponse,
        summary="Get attacker profile",
        description="Returns detailed profile for a specific attacker IP.",
        tags=["attackers"],
    )
    async def get_attacker(
        request: Request,
        attacker_ip: str,
    ) -> AttackerProfileResponse:
        profiler = request.app.state.attacker_profiler

        if profiler is None:
            raise HTTPException(
                status_code=503,
                detail="Attacker profiler not available",
            )

        # Build or refresh profile
        try:
            profile = await profiler.profile_attacker(attacker_ip)
        except Exception as exc:
            logger.error("Failed to profile attacker %s: %s", attacker_ip, exc)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to build profile for {attacker_ip}",
            ) from exc

        if profile.interaction_count == 0:
            raise HTTPException(
                status_code=404,
                detail=f"No interactions found for attacker '{attacker_ip}'",
            )

        return _profile_to_response(profile)

    @router.get(
        "/attackers/{attacker_ip}/timeline",
        response_model=AttackTimelineResponse,
        summary="Get attacker timeline",
        description="Returns chronological attack timeline for an attacker.",
        tags=["attackers"],
    )
    async def get_attacker_timeline(
        request: Request,
        attacker_ip: str,
    ) -> AttackTimelineResponse:
        profiler = request.app.state.attacker_profiler

        if profiler is None:
            return AttackTimelineResponse(
                attacker_ip=attacker_ip,
                events=[],
                total_events=0,
            )

        try:
            timeline = await profiler.get_attack_timeline(attacker_ip)
        except Exception as exc:
            logger.error("Failed to get timeline for %s: %s", attacker_ip, exc)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to retrieve timeline for {attacker_ip}",
            ) from exc

        return AttackTimelineResponse(
            attacker_ip=attacker_ip,
            events=[
                AttackTimelineEvent(
                    sequence=e["sequence"],
                    timestamp=e["timestamp"],
                    type=e["type"],
                    protocol=e["protocol"],
                    payload=e["payload"],
                    response_preview=e["response_preview"],
                    honeypot_id=e["honeypot_id"],
                    session_id=e["session_id"],
                )
                for e in timeline
            ],
            total_events=len(timeline),
        )

    # ── Sessions ────────────────────────────────────────────────────────

    @router.get(
        "/sessions",
        response_model=list[dict[str, Any]],
        summary="List sessions",
        description="Returns active and recent sessions.",
        tags=["sessions"],
    )
    async def list_sessions(request: Request) -> list[dict[str, Any]]:
        """List all sessions derived from interaction logs."""
        interaction_logger = request.app.state.interaction_logger

        if interaction_logger is None:
            return []

        # Get all interactions and group by session
        interactions = interaction_logger.get_interactions(limit=10000)
        sessions: dict[str, dict[str, Any]] = {}

        for i in interactions:
            sid = i.session_id or "unknown"
            if sid not in sessions:
                sessions[sid] = {
                    "session_id": sid,
                    "attacker_ip": i.attacker_ip,
                    "honeypot_id": i.honeypot_id,
                    "started_at": i.timestamp.isoformat(),
                    "interaction_count": 0,
                    "protocols": set(),
                }
            sessions[sid]["interaction_count"] += 1
            sessions[sid]["protocols"].add(i.protocol)
            if i.timestamp.isoformat() > sessions[sid].get("last_seen", ""):
                sessions[sid]["last_seen"] = i.timestamp.isoformat()

        result = []
        for s in sessions.values():
            s["protocols"] = list(s["protocols"])
            result.append(s)

        return sorted(result, key=lambda x: x.get("last_seen", ""), reverse=True)

    @router.get(
        "/sessions/{session_id}/logs",
        response_model=InteractionListResponse,
        summary="Get session logs",
        description="Returns all interactions for a specific session.",
        tags=["sessions"],
    )
    async def get_session_logs(
        request: Request,
        session_id: str,
        limit: int = Query(default=100, ge=1, le=10000),
        offset: int = Query(default=0, ge=0),
    ) -> InteractionListResponse:
        interaction_logger = request.app.state.interaction_logger

        if interaction_logger is None:
            return InteractionListResponse(
                interactions=[], total=0, limit=limit, offset=offset
            )

        interactions = interaction_logger.get_interactions(
            session_id=session_id,
            limit=limit,
            offset=offset,
        )

        return InteractionListResponse(
            interactions=[
                InteractionResponse(
                    id=i.id,
                    session_id=i.session_id,
                    honeypot_id=i.honeypot_id,
                    timestamp=i.timestamp,
                    attacker_ip=i.attacker_ip,
                    protocol=i.protocol,
                    interaction_type=ApiInteractionType(i.interaction_type.value),
                    payload=i.payload,
                    response_preview=i.response[:200] if i.response else "",
                    parsed_command=i.parsed_command,
                    user_context=i.user_context,
                )
                for i in interactions
            ],
            total=len(interactions),
            limit=limit,
            offset=offset,
        )

    # ── Metrics ─────────────────────────────────────────────────────────

    @router.get(
        "/metrics",
        response_class=PlainTextResponse,
        summary="Prometheus metrics",
        description="Returns Prometheus-formatted metrics for monitoring.",
        tags=["metrics"],
    )
    async def get_metrics(request: Request) -> str:
        """Generate Prometheus-compatible metrics output.

        Exposes server-specific metrics:
        - securenet_interactions_total
        - securenet_unique_attackers
        - emberhoneypot_attacks_blocked_total
        - securenet_ttp_extracted_total
        - emberhoneypot_feeds_published_total
        - securenet_personas_active
        - securenet_deception_success_rate
        - securenet_instances_total
        - securenet_engine_running
        """
        engine = request.app.state.engine
        interaction_logger = getattr(request.app.state, "interaction_logger", None)
        profiler = getattr(request.app.state, "attacker_profiler", None)
        collector: MetricsCollector = _metrics_collector

        lines: list[str] = []

        # ── Active servers gauge ──
        active_by_type: dict[str, int] = {}
        total_active = 0
        for instance in await engine.list_instances():
            if instance.status.value == "active":
                t = instance.type.value
                active_by_type[t] = active_by_type.get(t, 0) + 1
                total_active += 1

        lines.append(
            "# HELP securenet_personas_active "
            "Number of active deception personas"
        )
        lines.append("# TYPE securenet_personas_active gauge")
        lines.append(f"securenet_personas_active {total_active}")

        lines.append(
            "# HELP securenet_instances_total "
            "Total server instances managed"
        )
        lines.append("# TYPE securenet_instances_total counter")
        lines.append(f"securenet_instances_total {engine.active_instance_count}")

        # ── Active by type ──
        lines.append(
            "\n# HELP server_active_instances "
            "Number of active server instances by service type"
        )
        lines.append("# TYPE server_active_instances gauge")
        for t, count in active_by_type.items():
            lines.append(f'server_active_instances{{service_type="{t}"}} {count}')
        lines.append(
            f'server_active_instances{{service_type="total"}} '
            f"{sum(active_by_type.values())}"
        )

        # ── Total interactions ──
        total_interactions = 0
        if interaction_logger is not None:
            total_interactions = interaction_logger.get_interaction_count()

        lines.append(
            "\n# HELP securenet_interactions_total "
            "Total interactions observed"
        )
        lines.append("# TYPE securenet_interactions_total counter")
        lines.append(f"securenet_interactions_total {total_interactions}")

        # ── Unique attackers ──
        unique_attackers = 0
        if interaction_logger is not None:
            unique_attackers = len(interaction_logger.get_unique_attackers())

        lines.append(
            "\n# HELP securenet_unique_attackers "
            "Unique attacker IPs observed"
        )
        lines.append("# TYPE securenet_unique_attackers gauge")
        lines.append(f"securenet_unique_attackers {unique_attackers}")

        # ── Engine status ──
        lines.append(
            "\n# HELP securenet_engine_running "
            "Engine running status (1=running)"
        )
        lines.append("# TYPE securenet_engine_running gauge")
        lines.append(f"securenet_engine_running {1 if engine.is_running else 0}")

        # ── TTPs extracted ──
        ttp_count = 0
        if profiler is not None:
            profiles = await profiler.get_all_profiles()
            for p in profiles:
                ttp_count += len(p.ttp_list)

        lines.append(
            "\n# HELP securenet_ttp_extracted "
            "TTPs extracted from attacker sessions"
        )
        lines.append("# TYPE securenet_ttp_extracted counter")
        lines.append(f"securenet_ttp_extracted {ttp_count}")

        # ── Deception success rate ──
        deception_rate = 0.0
        if total_interactions > 0 and unique_attackers > 0:
            deception_rate = min(100.0, (total_interactions / max(unique_attackers, 1)) * 10)

        lines.append(
            "\n# HELP securenet_deception_success_rate "
            "Percentage of attackers successfully deceived"
        )
        lines.append("# TYPE securenet_deception_success_rate gauge")
        lines.append(f"securenet_deception_success_rate {deception_rate:.2f}")

        # ── Append any metrics from the shared collector ──
        collector_lines = collector.export_prometheus()
        if collector_lines:
            lines.append("")
            lines.append(collector_lines.rstrip("\n"))

        return "\n".join(lines) + "\n"

    return router


# ── Conversion Helpers ───────────────────────────────────────────────────


def _instance_to_response(instance: Any) -> HoneypotResponse:
    """Convert a core HoneypotInstance to an API response model."""
    return HoneypotResponse(
        id=instance.id,
        type=ApiHoneypotType(instance.type.value),
        status=ApiInstanceStatus(instance.status.value),
        persona=DecoyPersonaResponse(
            id=instance.persona.id,
            role=instance.persona.role,
            name=instance.persona.name,
            username=instance.persona.username,
            password_hint=instance.persona.password_hint,
            ssh_keys=instance.persona.ssh_keys,
            file_preferences=instance.persona.file_preferences,
            typical_commands=instance.persona.typical_commands,
            environment_vars=instance.persona.environment_vars,
            fake_projects=instance.persona.fake_projects,
        ),
        network_zone=instance.network_zone,
        exposed_ports=instance.exposed_ports,
        container_id=instance.container_id,
        created_at=instance.created_at,
        expires_at=instance.expires_at,
        banner=instance.banner,
        version_string=instance.version_string,
        metrics=InstanceMetricsResponse(
            interaction_count=instance.metrics.interaction_count,
            attacker_count=instance.metrics.attacker_count,
            command_count=instance.metrics.command_count,
            login_attempts=instance.metrics.login_attempts,
            login_successes=instance.metrics.login_successes,
            uptime_seconds=instance.metrics.uptime_seconds,
            last_interaction_at=instance.metrics.last_interaction_at,
        ),
    )


def _profile_to_response(profile: Any) -> AttackerProfileResponse:
    """Convert a core AttackerProfile to an API response model."""
    return AttackerProfileResponse(
        ip=profile.ip,
        first_seen=profile.first_seen,
        last_seen=profile.last_seen,
        interaction_count=profile.interaction_count,
        total_commands=profile.total_commands,
        unique_commands=profile.unique_commands,
        sophistication=profile.sophistication,
        sophistication_level=ApiSophisticationLevel(profile.sophistication_level.value),
        threat_score=profile.threat_score,
        ttp_list=[
            TTPResponse(
                tactic=t.tactic,
                tactic_id=t.tactic_id,
                technique=t.technique,
                technique_id=t.technique_id,
                confidence=t.confidence,
                evidence_count=len(t.evidence),
            )
            for t in profile.ttp_list
        ],
        tools_detected=[
            ToolDetectionResponse(
                name=t.name,
                confidence=t.confidence,
                evidence_count=len(t.evidence),
            )
            for t in profile.tools_detected
        ],
        intents=profile.intents,
        favorite_commands=profile.favorite_commands,
    )
