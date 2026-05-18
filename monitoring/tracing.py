"""
Request Tracing for SecureNet.

Provides correlation-ID management and operation tracing using Python's
:mod:`contextvars` for safe propagation across async boundaries.

Usage::

    from secure_net.monitoring.tracing import Tracer

    tracer = Tracer()

    # Context-manager style
    with tracer.trace("server_session", session="abc-123"):
        handle_session()

    # Or manual control
    cid = tracer.get_correlation_id() or tracer.generate_id()
    tracer.set_correlation_id(cid)
"""

from __future__ import annotations

import contextvars
import logging
import time
import uuid
from contextlib import contextmanager
from typing import Any, Generator

logger = logging.getLogger("secure_net.tracing")

# Context variable holding the current correlation ID for this task.
# Using ContextVar ensures safe propagation across async/await boundaries
# without leaking between concurrent tasks.
_correlation_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id", default=None
)


class Tracer:
    """Simple request tracer with correlation IDs.

    Uses :class:`contextvars.ContextVar` so correlation IDs are scoped to
    individual async tasks and do not leak across concurrent requests.

    Example::

        tracer = Tracer()

        @app.get("/api/servers")
        async def list_servers():
            with tracer.trace("list_honeypots"):
                await fetch_servers()
            return {"ok": True}
    """

    def __init__(self, service_name: str = "secure_net") -> None:
        self.service_name = service_name

    # ------------------------------------------------------------------
    # Correlation ID management
    # ------------------------------------------------------------------

    def get_correlation_id(self) -> str | None:
        """Get current correlation ID from context."""
        return _correlation_id_var.get()

    def set_correlation_id(self, cid: str) -> None:
        """Set correlation ID in context.

        The ID will be visible to all code running in the same async context
        (same task), including logging formatters and downstream service calls.
        """
        _correlation_id_var.set(cid)

    def generate_id(self) -> str:
        """Generate a new UUID4 correlation ID."""
        return str(uuid.uuid4())

    def clear(self) -> None:
        """Remove correlation ID from current context."""
        _correlation_id_var.set(None)

    # ------------------------------------------------------------------
    # Operation tracing
    # ------------------------------------------------------------------

    @contextmanager
    def trace(
        self,
        operation: str,
        **kwargs: Any,
    ) -> Generator[dict[str, Any], None, None]:
        """Context manager for tracing an operation.

        Emits ``start`` and ``end`` log events with timing and any extra
        key-value pairs provided.

        Args:
            operation: Name of the operation (e.g. ``"server_session"``).
            **kwargs: Additional key-value pairs to include in log records.

        Yields:
            Mutable dict that can be updated with intermediate results.

        Example::

            with tracer.trace("server_session", session="abc-123") as span:
                result = await handle_session(session)
                span["commands_seen"] = len(result.commands)
        """
        cid = self.get_correlation_id()
        if cid is None:
            cid = self.generate_id()
            self.set_correlation_id(cid)

        span_data: dict[str, Any] = {
            "operation": operation,
            "correlation_id": cid,
            "service": self.service_name,
            **kwargs,
        }

        start = time.perf_counter()
        logger.info(
            f"Trace start: {operation}",
            extra={"correlation_id": cid, "extra": {**span_data, "event": "start"}},
        )

        try:
            yield span_data
        except Exception as exc:
            elapsed = time.perf_counter() - start
            span_data["duration_ms"] = round(elapsed * 1000, 2)
            span_data["event"] = "error"
            span_data["error"] = str(exc)
            logger.error(
                f"Trace error: {operation} -- {exc}",
                extra={"correlation_id": cid, "extra": span_data},
                exc_info=True,
            )
            raise
        else:
            elapsed = time.perf_counter() - start
            span_data["duration_ms"] = round(elapsed * 1000, 2)
            span_data["event"] = "end"
            logger.info(
                f"Trace end: {operation} ({span_data['duration_ms']}ms)",
                extra={"correlation_id": cid, "extra": span_data},
            )

    # ------------------------------------------------------------------
    # Decorator helper
    # ------------------------------------------------------------------

    def trace_async(
        self,
        operation: str | None = None,
        **default_kwargs: Any,
    ) -> Any:
        """Decorator to trace an async function.

        Example::

            @tracer.trace_async("server_spawn", type="ssh")
            async def spawn_server(persona: DecoyPersona):
                ...
        """
        def decorator(fn: Any) -> Any:
            op_name = operation or fn.__name__

            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                trace_kwargs = {**default_kwargs, **kwargs}
                with self.trace(op_name, **trace_kwargs):
                    return await fn(*args, **kwargs)

            wrapper.__name__ = fn.__name__
            wrapper.__doc__ = fn.__doc__
            return wrapper

        return decorator

    def trace_sync(
        self,
        operation: str | None = None,
        **default_kwargs: Any,
    ) -> Any:
        """Decorator to trace a sync function.

        Example::

            @tracer.trace_sync("parse_config")
            def load_config(path: str):
                ...
        """
        def decorator(fn: Any) -> Any:
            op_name = operation or fn.__name__

            def wrapper(*args: Any, **kwargs: Any) -> Any:
                trace_kwargs = {**default_kwargs, **kwargs}
                with self.trace(op_name, **trace_kwargs):
                    return fn(*args, **kwargs)

            wrapper.__name__ = fn.__name__
            wrapper.__doc__ = fn.__doc__
            return wrapper

        return decorator
