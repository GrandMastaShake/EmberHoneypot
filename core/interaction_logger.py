"""
Interaction Logger — captures every attacker interaction with SQLite persistence.

Track 2a: SecureNet Core + API Layer
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Any



from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ── Pydantic Models ──────────────────────────────────────────────────────


class InteractionType(str, Enum):
    """Classification of interaction types."""

    COMMAND = "command"
    QUERY = "query"
    FILE_ACCESS = "file_access"
    NETWORK = "network"
    LOGIN = "login"
    HTTP_REQUEST = "http_request"
    AUTH_ATTEMPT = os.environ.get("SRV_AUTH_ATTEMPT_TYPE", "auth_attempt")


class InteractionLog(BaseModel):
    """A single captured interaction between an attacker and a honeypot."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    honeypot_id: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sequence_number: int = 0

    # Attacker info
    attacker_ip: str = ""
    attacker_id: str = ""
    source_port: int = 0
    destination_port: int = 0

    # Content
    interaction_type: InteractionType = InteractionType.COMMAND
    protocol: str = "tcp"  # tcp | udp
    payload: str = ""  # The raw input from attacker
    response: str = ""  # What we sent back
    parsed_command: str = ""  # Structured command if applicable

    # Context
    working_directory: str = ""
    user_context: str = ""  # Authenticated user if known
    environment: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True}


# ── InteractionLogger ────────────────────────────────────────────────────


class InteractionLogger:
    """Captures and persists every interaction at maximum fidelity.

    Uses SQLite for the MVP (zero external dependencies) with a clean
    migration path to PostgreSQL via the shared BaseModel schema.
    """

    def __init__(self, db_path: str = "./server_logs.db") -> None:
        safe_file = os.path.basename(db_path) if '..' in db_path or '/' in db_path else db_path
        self.db_path = f"/var/lib/secure_net/{safe_file}"
        self._local = threading.local()
        self._init_db()

    # ── Database ──────────────────────────────────────────────────────────

    @contextmanager
    def _connection(self):
        """Thread-safe SQLite connection context manager."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        try:
            yield self._local.conn
        except Exception:
            self._local.conn.rollback()
            raise

    def _init_db(self) -> None:
        """Initialize SQLite schema."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS interactions (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    honeypot_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    sequence_number INTEGER DEFAULT 0,
                    attacker_ip TEXT NOT NULL,
                    attacker_id TEXT DEFAULT '',
                    source_port INTEGER DEFAULT 0,
                    destination_port INTEGER DEFAULT 0,
                    interaction_type TEXT NOT NULL,
                    protocol TEXT DEFAULT 'tcp',
                    payload TEXT DEFAULT '',
                    response TEXT DEFAULT '',
                    parsed_command TEXT DEFAULT '',
                    working_directory TEXT DEFAULT '',
                    user_context TEXT DEFAULT '',
                    environment TEXT DEFAULT '{}',
                    metadata TEXT DEFAULT '{}'
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_interactions_ip
                ON interactions(attacker_ip)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_interactions_honeypot
                ON interactions(honeypot_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_interactions_session
                ON interactions(session_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_interactions_timestamp
                ON interactions(timestamp)
                """
            )
            conn.commit()
            logger.info("Interaction database initialized at %s", self.db_path)

    # ── Logging ───────────────────────────────────────────────────────────

    def log_interaction(
        self,
        attacker_ip: str,
        timestamp: datetime | None,
        protocol: str,
        payload: str,
        response: str,
        **kwargs: Any,
    ) -> InteractionLog:
        """Log a single interaction.

        Args:
            attacker_ip: Source IP address of the attacker.
            timestamp: When the interaction occurred. Defaults to now.
            protocol: Protocol used (tcp, udp, ssh, http, etc.).
            payload: Raw input from the attacker.
            response: Response sent back to the attacker.
            **kwargs: Additional fields (session_id, honeypot_id,
                     interaction_type, source_port, destination_port, etc.)

        Returns:
            The created InteractionLog entry.
        """
        ts = timestamp or datetime.now(timezone.utc)

        entry = InteractionLog(
            attacker_ip=attacker_ip,
            timestamp=ts,
            protocol=protocol,
            payload=payload,
            response=response,
            session_id=kwargs.get("session_id", ""),
            honeypot_id=kwargs.get("honeypot_id", ""),
            interaction_type=kwargs.get("interaction_type", InteractionType.COMMAND),
            source_port=kwargs.get("source_port", 0),
            destination_port=kwargs.get("destination_port", 0),
            parsed_command=kwargs.get("parsed_command", ""),
            working_directory=kwargs.get("working_directory", ""),
            user_context=kwargs.get("user_context", ""),
            environment=kwargs.get("environment", {}),
            metadata=kwargs.get("metadata", {}),
        )

        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO interactions
                (id, session_id, honeypot_id, timestamp, sequence_number,
                 attacker_ip, attacker_id, source_port, destination_port,
                 interaction_type, protocol, payload, response, parsed_command,
                 working_directory, user_context, environment, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.id,
                    entry.session_id,
                    entry.honeypot_id,
                    entry.timestamp.isoformat(),
                    entry.sequence_number,
                    entry.attacker_ip,
                    entry.attacker_id,
                    entry.source_port,
                    entry.destination_port,
                    entry.interaction_type.value,
                    entry.protocol,
                    entry.payload,
                    entry.response,
                    entry.parsed_command,
                    entry.working_directory,
                    entry.user_context,
                    json.dumps(entry.environment),
                    json.dumps(entry.metadata),
                ),
            )
            conn.commit()

        logger.debug(
            "Logged interaction [%s] from %s: %s",
            entry.interaction_type.value,
            attacker_ip,
            payload[:80],
        )
        return entry

    # ── Queries ───────────────────────────────────────────────────────────

    def get_interactions(
        self,
        attacker_ip: str | None = None,
        protocol: str | None = None,
        honeypot_id: str | None = None,
        session_id: str | None = None,
        interaction_type: InteractionType | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[InteractionLog]:
        """Query interactions with optional filters.

        Args:
            attacker_ip: Filter by source IP.
            protocol: Filter by protocol (tcp, udp, ssh, http).
            honeypot_id: Filter by honeypot instance.
            session_id: Filter by session ID.
            interaction_type: Filter by type of interaction.
            limit: Maximum results to return.
            offset: Pagination offset.

        Returns:
            List of matching InteractionLog entries.
        """
        conditions: list[str] = []
        params: list[Any] = []

        if attacker_ip:
            conditions.append("attacker_ip = ?")
            params.append(attacker_ip)
        if protocol:
            conditions.append("protocol = ?")
            params.append(protocol)
        if honeypot_id:
            conditions.append("honeypot_id = ?")
            params.append(honeypot_id)
        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if interaction_type:
            conditions.append("interaction_type = ?")
            params.append(interaction_type.value)

        query_parts = ["SELECT * FROM interactions"]
        if conditions:
            query_parts.append("WHERE")
            query_parts.append(" AND ".join(conditions))
        query_parts.append("ORDER BY timestamp DESC LIMIT ? OFFSET ?")
        query = " ".join(query_parts)

        with self._connection() as conn:
            cursor = conn.execute(query, (*params, limit, offset))
            rows = cursor.fetchall()

        return [self._row_to_model(row) for row in rows]

    def get_interaction_count(
        self,
        attacker_ip: str | None = None,
        honeypot_id: str | None = None,
    ) -> int:
        """Get total interaction count for filtering."""
        conditions: list[str] = []
        params: list[Any] = []

        if attacker_ip:
            conditions.append("attacker_ip = ?")
            params.append(attacker_ip)
        if honeypot_id:
            conditions.append("honeypot_id = ?")
            params.append(honeypot_id)

        query_parts = ["SELECT COUNT(*) FROM interactions"]
        if conditions:
            query_parts.append("WHERE")
            query_parts.append(" AND ".join(conditions))
        query = " ".join(query_parts)

        with self._connection() as conn:
            cursor = conn.execute(query, params)
            row = cursor.fetchone()
            return row[0] if row else 0

    def get_unique_attackers(self) -> list[str]:
        """Return list of all unique attacker IPs."""
        with self._connection() as conn:
            cursor = conn.execute(
                "SELECT DISTINCT attacker_ip FROM interactions ORDER BY attacker_ip"
            )
            return [row[0] for row in cursor.fetchall()]

    # ── Export ────────────────────────────────────────────────────────────

    def export_logs(self, fmt: str = "json") -> str:
        """Export all interaction logs in the requested format.

        Args:
            fmt: Output format — "json" or "csv".

        Returns:
            Serialized log data.

        Raises:
            ValueError: If format is not supported.
        """
        interactions = self.get_interactions(limit=100000)

        if fmt.lower() == "json":
            return json.dumps(
                [i.model_dump(mode="json") for i in interactions],
                indent=2,
                default=str,
            )

        if fmt.lower() == "csv":
            lines = [
                "id,timestamp,attacker_ip,protocol,interaction_type,payload,response"
            ]
            for i in interactions:
                safe_payload = i.payload.replace('"', "'").replace("\n", " ")[:200]
                safe_response = i.response.replace('"', "'").replace("\n", " ")[:200]
                lines.append(
                    f'"{i.id}",{i.timestamp.isoformat()},"{i.attacker_ip}",'
                    f'"{i.protocol}","{i.interaction_type.value}",'
                    f'"{safe_payload}",'
                    f'"{safe_response}"'
                )
            return "\n".join(lines)

        raise ValueError(f"Unsupported export format: {fmt}. Use 'json' or 'csv'.")

    # ── Session Timeline ──────────────────────────────────────────────────

    def get_session_timeline(self, session_id: str) -> list[InteractionLog]:
        """Get chronological reconstruction of a session.

        Args:
            session_id: The session to reconstruct.

        Returns:
            Ordered list of interactions for the session.
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM interactions
                WHERE session_id = ?
                ORDER BY timestamp ASC, sequence_number ASC
                """,
                (session_id,),
            )
            rows = cursor.fetchall()

        return [self._row_to_model(row) for row in rows]

    # ── Helpers ───────────────────────────────────────────────────────────

    def _row_to_model(self, row: sqlite3.Row) -> InteractionLog:
        """Convert a SQLite row to an InteractionLog model."""
        return InteractionLog(
            id=row["id"],
            session_id=row["session_id"],
            honeypot_id=row["honeypot_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            sequence_number=row["sequence_number"],
            attacker_ip=row["attacker_ip"],
            attacker_id=row["attacker_id"],
            source_port=row["source_port"],
            destination_port=row["destination_port"],
            interaction_type=InteractionType(row["interaction_type"]),
            protocol=row["protocol"],
            payload=row["payload"],
            response=row["response"],
            parsed_command=row["parsed_command"],
            working_directory=row["working_directory"],
            user_context=row["user_context"],
            environment=json.loads(row["environment"] or "{}"),
            metadata=json.loads(row["metadata"] or "{}"),
        )

    def close(self) -> None:
        """Close database connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
