"""
WebSocket attack feed — real-time streaming of attacker interactions.

Track 2a: EmberHoneypot Core + API Layer
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from ember_honeypot.api.models import AttackEvent

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections with channel-based subscriptions."""

    def __init__(self) -> None:
        self._connections: dict[str, WebSocket] = {}
        self._channels: dict[str, set[str]] = {}  # channel -> set of connection_ids
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, connection_id: str) -> None:
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            self._connections[connection_id] = websocket
        logger.debug("WebSocket connection %s accepted", connection_id)

    async def disconnect(self, connection_id: str) -> None:
        """Unregister and clean up a WebSocket connection."""
        async with self._lock:
            self._connections.pop(connection_id, None)
            for channel_subs in self._channels.values():
                channel_subs.discard(connection_id)
        logger.debug("WebSocket connection %s disconnected", connection_id)

    def subscribe(self, connection_id: str, channel: str) -> None:
        """Subscribe a connection to a channel."""
        if channel not in self._channels:
            self._channels[channel] = set()
        self._channels[channel].add(connection_id)
        logger.debug("Connection %s subscribed to channel '%s'", connection_id, channel)

    def unsubscribe(self, connection_id: str, channel: str) -> None:
        """Unsubscribe a connection from a channel."""
        if channel in self._channels:
            self._channels[channel].discard(connection_id)

    async def broadcast(self, channel: str, message: str) -> None:
        """Broadcast a message to all subscribers of a channel."""
        if channel not in self._channels:
            return

        connection_ids = list(self._channels[channel])
        for conn_id in connection_ids:
            websocket = self._connections.get(conn_id)
            if websocket is None:
                continue
            try:
                await websocket.send_text(message)
            except Exception:
                logger.debug("Failed to send to %s, removing", conn_id)
                await self.disconnect(conn_id)

    @property
    def connection_count(self) -> int:
        """Total number of active connections."""
        return len(self._connections)

    @property
    def channel_counts(self) -> dict[str, int]:
        """Subscriber count per channel."""
        return {ch: len(subs) for ch, subs in self._channels.items()}


class AttackFeedManager:
    """Manages the real-time attack feed WebSocket endpoint.

    Maintains a connection manager and provides methods to broadcast
    attack events to all connected clients.
    """

    def __init__(self) -> None:
        self.manager = ConnectionManager()
        self._event_buffer: list[AttackEvent] = []
        self._buffer_size = 1000
        self._running = False

    async def start(self) -> None:
        """Start the attack feed manager."""
        self._running = True
        logger.info("AttackFeedManager started")

    async def stop(self) -> None:
        """Stop the attack feed manager."""
        self._running = False
        logger.info("AttackFeedManager stopped")

    async def handle_websocket(self, websocket: WebSocket) -> None:
        """Handle a WebSocket connection lifecycle.

        Args:
            websocket: The FastAPI WebSocket object.
        """
        connection_id = str(uuid.uuid4())
        await self.manager.connect(websocket, connection_id)

        try:
            # Send welcome message
            await websocket.send_json(
                {
                    "type": "connected",
                    "connection_id": connection_id,
                    "message": "Connected to EmberHoneypot attack feed",
                    "channels": ["attacks", "intel", "sessions"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )

            # Auto-subscribe to attacks channel
            self.manager.subscribe(connection_id, "attacks")

            # Send recent buffer
            for event in self._event_buffer[-50:]:
                await websocket.send_text(event.to_json())

            # Handle incoming messages
            while self._running:
                try:
                    data = await asyncio.wait_for(
                        websocket.receive_text(),
                        timeout=30.0,
                    )
                    await self._handle_client_message(connection_id, data, websocket)
                except asyncio.TimeoutError:
                    # Send heartbeat
                    try:
                        await websocket.send_json(
                            {
                                "type": "heartbeat",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }
                        )
                    except Exception:
                        break

        except WebSocketDisconnect:
            logger.debug("WebSocket %s disconnected by client", connection_id)
        except Exception as exc:
            logger.warning("WebSocket %s error: %s", connection_id, exc)
        finally:
            await self.manager.disconnect(connection_id)

    async def _handle_client_message(
        self,
        connection_id: str,
        data: str,
        websocket: WebSocket,
    ) -> None:
        """Process a message from a connected client.

        Supports:
        - subscribe: {"type": "subscribe", "channel": "attacks"}
        - unsubscribe: {"type": "unsubscribe", "channel": "attacks"}
        - ping: {"type": "ping"}
        """
        try:
            msg = json.loads(data)
            msg_type = msg.get("type", "")

            if msg_type == "subscribe":
                channel = msg.get("channel", "attacks")
                self.manager.subscribe(connection_id, channel)
                await websocket.send_json(
                    {"type": "subscribed", "channel": channel}
                )

            elif msg_type == "unsubscribe":
                channel = msg.get("channel", "attacks")
                self.manager.unsubscribe(connection_id, channel)
                await websocket.send_json(
                    {"type": "unsubscribed", "channel": channel}
                )

            elif msg_type == "ping":
                await websocket.send_json(
                    {
                        "type": "pong",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )

            else:
                await websocket.send_json(
                    {"type": "error", "message": f"Unknown message type: {msg_type}"}
                )

        except json.JSONDecodeError:
            await websocket.send_json(
                {"type": "error", "message": "Invalid JSON"}
            )

    async def broadcast_event(self, event: AttackEvent) -> None:
        """Broadcast an attack event to all subscribers.

        Args:
            event: The attack event to broadcast.
        """
        if not self._running:
            return

        # Buffer event
        self._event_buffer.append(event)
        if len(self._event_buffer) > self._buffer_size:
            self._event_buffer = self._event_buffer[-self._buffer_size // 2:]

        # Broadcast
        await self.manager.broadcast("attacks", event.to_json())

    async def broadcast_interaction(
        self,
        attacker_ip: str,
        honeypot_id: str,
        honeypot_type: str,
        payload: str,
        interaction_type: str,
        protocol: str,
        threat_score: int = 0,
        sophistication: float = 0.0,
        ttp_detected: list[str] | None = None,
    ) -> None:
        """Create and broadcast an interaction event.

        Convenience method for broadcasting from the core engine.
        """
        event = AttackEvent(
            event_type="interaction",
            timestamp=datetime.now(timezone.utc).isoformat(),
            attacker_ip=attacker_ip,
            honeypot_id=honeypot_id,
            honeypot_type=honeypot_type,
            payload=payload[:500],
            interaction_type=interaction_type,
            protocol=protocol,
            threat_score=threat_score,
            sophistication=sophistication,
            ttp_detected=ttp_detected or [],
        )
        await self.broadcast_event(event)

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def subscriber_count(self) -> int:
        return self.manager.connection_count

    @property
    def buffered_event_count(self) -> int:
        return len(self._event_buffer)


# ── FastAPI Integration ──────────────────────────────────────────────────


def register_websocket_routes(app: FastAPI, feed_manager: AttackFeedManager) -> None:
    """Register WebSocket routes on a FastAPI application.

    Args:
        app: The FastAPI application.
        feed_manager: The AttackFeedManager instance to use.
    """

    @app.websocket("/ws/attacks")
    async def websocket_attacks(websocket: WebSocket) -> None:
        """Real-time attack feed WebSocket endpoint.

        Streams all new attacker interactions in real-time.
        Clients can subscribe/unsubscribe to channels.
        """
        await feed_manager.handle_websocket(websocket)

    @app.websocket("/ws/live/attacks")
    async def websocket_attacks_compat(websocket: WebSocket) -> None:
        """Compatibility alias for /ws/attacks (spec-matching path)."""
        await feed_manager.handle_websocket(websocket)
