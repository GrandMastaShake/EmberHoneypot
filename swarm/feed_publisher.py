"""
FeedPublisher -- EmberHoneypot-side intelligence bridge to Corporeus.

Publishes honeypot attack events to Corporeus's threat feed.
When an attack is captured, this publisher:
1. Formats the attack as a HoneyPotEvent
2. Sends it to Corporeus (or queues for batch delivery)
3. Tracks delivery status

Resilience::
    - If Corporeus is down, events are queued locally
    - Queue has a max size (drops oldest when full)
    - Periodic flush retries queued events
    - Batch endpoint for efficient bulk delivery

Architecture::

    HoneypotEngine (captures attack)
        |
        | InteractionLog
        v
    FeedPublisher.publish_attack()
        |
        | 1. classify_attack() -> attack_type
        | 2. convert_interaction() -> HoneyPotEvent dict
        | 3. POST /swarm/honeypot/event
        v
    Corporeus (HoneyPotFeed)
        |
        | Queue if Corporeus down
        v
    Periodic flush_queue()
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections import deque
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocol for InteractionLog duck-typing
# ---------------------------------------------------------------------------


@runtime_checkable
class _InteractionLike(Protocol):
    """Protocol for interaction objects that can be published.

    Accepts both core.interaction_logger.InteractionLog and
    models.interaction.InteractionLog without importing either.
    """

    @property
    def attacker_ip(self) -> str: ...

    @property
    def payload(self) -> str: ...

    @property
    def protocol(self) -> str: ...

    @property
    def interaction_type(self) -> Any: ...

    @property
    def session_id(self) -> Any: ...

    @property
    def honeypot_id(self) -> Any: ...

    @property
    def working_directory(self) -> str: ...

    @property
    def parsed_command(self) -> Any: ...

    @property
    def metadata(self) -> dict[str, Any]: ...


# ---------------------------------------------------------------------------
# FeedPublisher
# ---------------------------------------------------------------------------


class FeedPublisher:
    """Publishes honeypot attack events to Corporeus's threat feed.

    When an attack is captured, this publisher:
    1. Formats the attack as a HoneyPotEvent
    2. Sends it to Corporeus (or queues for batch delivery)
    3. Tracks delivery status

    Resilience features:
        - Queue with max size (drops oldest when full)
        - Immediate delivery with fallback to queue
        - Batch flush endpoint for bulk delivery
        - Configurable timeout and retry
    """

    # Corporeus endpoint paths
    EVENT_ENDPOINT = "/swarm/honeypot/event"
    BATCH_ENDPOINT = "/swarm/honeypot/batch"

    def __init__(
        self,
        corporeus_endpoint: str | None = None,
        max_queue_size: int = 100,
        request_timeout: float = 5.0,
        batch_timeout: float = 10.0,
        auto_flush_interval: float = 30.0,
    ) -> None:
        """Initialize the feed publisher.

        Args:
            corporeus_endpoint: Corporeus API base URL.
                Falls back to CORPOREUS_ENDPOINT env var, then localhost.
            max_queue_size: Maximum queued events before dropping oldest.
            request_timeout: Timeout for single event POST (seconds).
            batch_timeout: Timeout for batch POST (seconds).
            auto_flush_interval: Seconds between automatic flush attempts.
                Set to 0.0 to disable auto-flush.
        """
        self.endpoint = corporeus_endpoint or os.environ.get(
            "CORPOREUS_ENDPOINT", "http://localhost:8001"
        )
        self._queue: deque[dict[str, Any]] = deque(maxlen=max_queue_size)
        self._max_queue_size = max_queue_size
        self._request_timeout = request_timeout
        self._batch_timeout = batch_timeout
        self._auto_flush_interval = auto_flush_interval
        self._total_published: int = 0
        self._total_queued: int = 0
        self._total_dropped: int = 0
        self._total_delivered: int = 0
        self._flush_task: asyncio.Task[None] | None = None
        self._running: bool = False

    # -- Lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        """Start the publisher, including auto-flush background task."""
        self._running = True
        if self._auto_flush_interval > 0:
            self._flush_task = asyncio.create_task(
                self._auto_flush_loop(), name="feed-publisher-flush"
            )
        logger.info(
            "FeedPublisher started -> %s (queue_size=%d, auto_flush=%.0fs)",
            self.endpoint,
            self._max_queue_size,
            self._auto_flush_interval,
        )

    async def stop(self) -> None:
        """Stop the publisher and flush remaining queued events."""
        self._running = False
        if self._flush_task is not None:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
            self._flush_task = None

        # Final flush attempt
        delivered = await self.flush_queue()
        logger.info(
            "FeedPublisher stopped. Final flush delivered %d events. "
            "Stats: published=%d, delivered=%d, queued=%d, dropped=%d",
            delivered,
            self._total_published,
            self._total_delivered,
            self._total_queued,
            self._total_dropped,
        )

    async def _auto_flush_loop(self) -> None:
        """Background task that periodically flushes the queue."""
        while self._running:
            try:
                await asyncio.sleep(self._auto_flush_interval)
                if self._queue:
                    delivered = await self.flush_queue()
                    if delivered:
                        logger.debug(
                            "Auto-flush delivered %d events to Corporeus", delivered
                        )
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Auto-flush error")

    # -- Publishing ----------------------------------------------------------

    async def publish_attack(self, interaction: Any) -> bool:
        """Publish an attack interaction to Corporeus.

        Args:
            interaction: Logged interaction from the honeypot.
                Can be core.interaction_logger.InteractionLog,
                models.interaction.InteractionLog, or any object
                matching the _InteractionLike protocol.

        Returns:
            True if published (or queued), False on error.
        """
        event = self._convert_interaction(interaction)
        self._total_published += 1

        # Try immediate delivery
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.endpoint}{self.EVENT_ENDPOINT}",
                    json=event,
                    timeout=self._request_timeout,
                )
                if resp.status_code == 200:
                    self._total_delivered += 1
                    logger.debug(
                        "Delivered event to Corporeus: %s", event.get("attack_type", "?")
                    )
                    return True
                else:
                    logger.warning(
                        "Corporeus returned %d for event", resp.status_code
                    )
        except httpx.ConnectError:
            logger.debug("Corporeus connection refused — queuing event")
        except httpx.TimeoutException:
            logger.debug("Corporeus timeout — queuing event")
        except Exception:
            logger.debug("Corporeus delivery error — queuing event", exc_info=True)

        # Queue for batch delivery (resilient fallback)
        if len(self._queue) >= self._max_queue_size:
            dropped = self._queue.popleft()
            self._total_dropped += 1
            logger.debug("Queue full — dropped oldest event")

        self._queue.append(event)
        self._total_queued += 1
        logger.debug("Queued event (queue: %d/%d)", len(self._queue), self._max_queue_size)
        return True  # True because we queued it successfully

    # -- Batch delivery ------------------------------------------------------

    async def flush_queue(self) -> int:
        """Flush all queued events to Corporeus in a single batch.

        Returns:
            Number of events successfully delivered.
        """
        if not self._queue:
            return 0

        events = list(self._queue)
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.endpoint}{self.BATCH_ENDPOINT}",
                    json={"events": events},
                    timeout=self._batch_timeout,
                )
                if resp.status_code == 200:
                    delivered = len(events)
                    self._queue.clear()
                    self._total_delivered += delivered
                    logger.info(
                        "Batch flush delivered %d events to Corporeus", delivered
                    )
                    return delivered
                else:
                    logger.warning(
                        "Corpereus batch endpoint returned %d", resp.status_code
                    )
        except httpx.ConnectError:
            logger.debug("Corporeus unavailable — %d events remain queued", len(events))
        except httpx.TimeoutException:
            logger.debug("Corporeus batch timeout — %d events remain queued", len(events))
        except Exception:
            logger.debug("Corporeus batch error", exc_info=True)

        return 0

    async def publish_batch(self, interactions: list[Any]) -> tuple[int, int]:
        """Publish multiple interactions — deliver what we can, queue the rest.

        Args:
            interactions: List of interaction objects.

        Returns:
            (delivered_now, queued) counts.
        """
        delivered = 0
        queued = 0
        for interaction in interactions:
            event = self._convert_interaction(interaction)
            self._total_published += 1

            # Try immediate delivery
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        f"{self.endpoint}{self.EVENT_ENDPOINT}",
                        json=event,
                        timeout=self._request_timeout,
                    )
                    if resp.status_code == 200:
                        delivered += 1
                        self._total_delivered += 1
                        continue
            except Exception:
                pass  # Fall through to queue

            # Queue the event
            if len(self._queue) >= self._max_queue_size:
                self._queue.popleft()
                self._total_dropped += 1
            self._queue.append(event)
            queued += 1
            self._total_queued += 1

        return delivered, queued

    # -- Conversion ----------------------------------------------------------

    def _convert_interaction(self, interaction: Any) -> dict[str, Any]:
        """Convert an interaction log to a HoneyPotEvent dict.

        Handles both core.interaction_logger.InteractionLog (str-based IDs)
        and models.interaction.InteractionLog (UUID-based IDs) without
        importing either module — pure duck-typing for zero coupling.
        """
        # Resolve fields with different names across InteractionLog variants
        attacker_ip = _getattr_chain(interaction, "attacker_ip", "source_ip", default="")
        payload = _getattr_chain(interaction, "payload", "raw_input", default="")
        parsed_command = _getattr_chain(interaction, "parsed_command", "parsed_command")

        # Resolve session/honeypot IDs (could be str or UUID)
        session_id = str(
            _getattr_chain(interaction, "session_id", default="")
        )
        honeypot_id = str(
            _getattr_chain(interaction, "honeypot_id", default="")
        )

        # Get working directory for target path inference
        working_directory = _getattr_chain(
            interaction, "working_directory", default=""
        )

        # Extract metadata-derived fields
        metadata = _getattr_chain(interaction, "metadata", default={}) or {}
        sophistication_score = metadata.get("sophistication_score", 0.5)
        attempt_count = metadata.get("attempt_count", 1)
        persona_name = metadata.get("persona_name", "unknown")

        # Map protocol/behavior to attack type
        attack_type = self._classify_attack(payload, interaction)

        # Derive target path from available context
        target_path = self._derive_target_path(
            working_directory, parsed_command, payload
        )

        # Resolve timestamp
        timestamp_raw = _getattr_chain(interaction, "timestamp", default=None)
        if timestamp_raw is not None:
            if isinstance(timestamp_raw, datetime):
                timestamp = timestamp_raw.isoformat()
            else:
                timestamp = str(timestamp_raw)
        else:
            timestamp = datetime.now(timezone.utc).isoformat()

        return {
            "attacker_ip": attacker_ip,
            "persona_name": persona_name,
            "attack_type": attack_type,
            "target_path": target_path,
            "payload": payload,
            "sophistication_score": float(sophistication_score),
            "attempt_count": int(attempt_count),
            "timestamp": timestamp,
            "session_id": session_id,
            "honeypot_id": honeypot_id,
        }

    # -- Attack classification -----------------------------------------------

    def _classify_attack(self, payload: str, interaction: Any) -> str:
        """Classify an interaction by attack type from payload analysis.

        Uses a keyword-based heuristic to categorize attacks into types
        that map to CWEs in the Corporeus HoneyPotFeed.
        """
        if not payload:
            return "reconnaissance"

        payload_lower = payload.lower()

        # Python code execution indicators (check FIRST — before xxe's "system(")
        python_cmd_keywords = {
            "os.system", "os.popen", "subprocess.call", "subprocess.run",
            "subprocess.popen", "__import__", "import os", "import subprocess",
            "pty.spawn", "socket.socket", "eval(", "exec(",
        }
        if any(kw in payload_lower for kw in python_cmd_keywords):
            return "command_injection"

        # SQL injection indicators (avoid matching Python string literals)
        sql_keywords = {
            "select ", "insert ", "update ", "delete ", "union ", "drop ",
            "create ", "alter ", "exec(", "execute(", ";--",
            "'or'", "'and'", "1=1", "sleep(", "benchmark(", "waitfor",
            "-- ", "/*", "*/", "@@", "information_schema",
            "xp_cmdshell", "exec master", "exec sp_", "sysobjects",
            "into outfile", "into dumpfile", "load_file(",
        }
        if any(kw in payload_lower for kw in sql_keywords):
            return "sql_injection"

        # XXE indicators (check before path traversal — "file:///" overlaps)
        # Note: "system(" is intentionally omitted — too broad (catches .system() calls)
        xxe_keywords = {
            "<!entity", "<!doctype", "system \"", "public \"",
            "<!element", "xinclude", "<!entity ", "<!doctype ",
        }
        if any(kw in payload_lower for kw in xxe_keywords):
            return "xxe"

        # Path traversal indicators
        path_keywords = {
            "../", "..\\", "/etc/passwd", "c:/windows", "c:\\\\windows",
            "\\..\\", "....//", "%2e%2e%2f", "%252e%252e%252f",
            "/proc/self", "boot.ini", "win.ini",
        }
        if any(kw in payload_lower for kw in path_keywords):
            return "path_traversal"

        # Generic command injection indicators (includes SSI exec)
        cmd_keywords = {
            ";", "|", "&&", "`", "$(", "${", ">/dev/tcp/",
            "bash -i", "sh -i", "nc -e", "python -c",
            "wget ", "curl ", "chmod +x", "/bin/sh", "/bin/bash",
            "<!--#exec", "#exec cmd=",
        }
        if any(kw in payload_lower for kw in cmd_keywords):
            return "command_injection"

        # XSS indicators (after command injection — "eval(" is command injection)
        xss_keywords = {
            "<script", "javascript:", "onerror=", "onload=", "alert(",
            "onmouseover=", "onclick=", "<img", "<svg", "<iframe",
            "document.cookie", "document.location",
        }
        if any(kw in payload_lower for kw in xss_keywords):
            return "xss"

        # Deserialization indicators
        deser_keywords = {
            "java.io.", "objectinputstream", "pickle.loads",
            "yaml.load", "__reduce__", "__class__", "__globals__",
            "commons-collections", "ysoserial",
        }
        if any(kw in payload_lower for kw in deser_keywords):
            return "deserialization"

        # SSRF indicators
        ssrf_keywords = {
            "http://169.254", "http://localhost", "http://127.0.0.1",
            "file:///", "ftp://internal", "http://0.0.0.0",
            "http://[::1]", "dict://", "gopher://",
        }
        if any(kw in payload_lower for kw in ssrf_keywords):
            return "ssrf"

        # Brute force indicators (multiple login attempts)
        interaction_type = str(
            _getattr_chain(interaction, "interaction_type", default="")
        ).lower()
        if "login" in interaction_type or "auth" in interaction_type:
            return "brute_force"
        xxe_keywords = {
            "<!entity", "<!doctype", "system(", "public(",
            "<!element", "xinclude",
        }
        if any(kw in payload_lower for kw in xxe_keywords):
            return "xxe"

        # Directory listing
        dir_keywords = {
            "index of", "directory listing", "parent directory",
            "?directory", "dir=", "list=1",
        }
        if any(kw in payload_lower for kw in dir_keywords):
            return "directory_listing"

        # Information disclosure
        info_keywords = {
            ".env", "config.json", "secret", "password", "api_key",
            "aws_access_key_id", "private_key", "internal",
        }
        if any(kw in payload_lower for kw in info_keywords):
            return "information_disclosure"

        return "reconnaissance"

    def _derive_target_path(
        self, working_directory: str, parsed_command: Any, payload: str
    ) -> str:
        """Derive a target path from available context."""
        if working_directory:
            return working_directory

        # Try to extract path from parsed command
        if parsed_command is not None:
            args = getattr(parsed_command, "arguments", None)
            if args and isinstance(args, (list, tuple)):
                for arg in args:
                    if arg and arg.startswith("/"):
                        return arg

        # Use payload prefix as fallback
        if payload and len(payload) < 200:
            return payload[:100]

        return "/"

    # -- Stats ---------------------------------------------------------------

    @property
    def queue_size(self) -> int:
        """Current number of queued events."""
        return len(self._queue)

    @property
    def is_healthy(self) -> bool:
        """Whether the publisher is operating normally.

        Returns False if the queue is critically full (>80%).
        """
        return len(self._queue) < (self._max_queue_size * 0.8)

    def get_stats(self) -> dict[str, Any]:
        """Return publisher statistics for monitoring."""
        return {
            "endpoint": self.endpoint,
            "total_published": self._total_published,
            "total_delivered": self._total_delivered,
            "total_queued": self._total_queued,
            "total_dropped": self._total_dropped,
            "queue_size": len(self._queue),
            "max_queue_size": self._max_queue_size,
            "queue_utilization": round(len(self._queue) / self._max_queue_size, 4),
            "is_healthy": self.is_healthy,
            "running": self._running,
        }


# ---------------------------------------------------------------------------
# Utility helpers (module-private)
# ---------------------------------------------------------------------------


def _getattr_chain(
    obj: Any, *names: str, default: Any = None
) -> Any:
    """Get the first available attribute from a chain of names.

    Handles both attribute access and dict-like access.
    """
    for name in names:
        try:
            val = getattr(obj, name, None)
            if val is not None:
                return val
        except (AttributeError, TypeError):
            # Try dict access for dict-like objects
            try:
                if name in obj:
                    return obj[name]
            except (TypeError, KeyError):
                pass
    return default
