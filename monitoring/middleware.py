"""
FastAPI Middleware for EmberHoneypot.

Provides timing, correlation-ID, metrics-collection, and structured-logging
middleware. All middleware classes are fully async and compatible with
FastAPI / Starlette.

Usage::

    from fastapi import FastAPI
    from ember_honeypot.monitoring.middleware import (
        TimingMiddleware,
        CorrelationIdMiddleware,
        MetricsMiddleware,
        LoggingMiddleware,
    )

    app = FastAPI()
    app.add_middleware(TimingMiddleware)
    app.add_middleware(CorrelationIdMiddleware)
    app.add_middleware(MetricsMiddleware, metrics_collector=collector)
    app.add_middleware(LoggingMiddleware)
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from .logging_config import get_correlation_id, set_correlation_id
from .metrics import MetricsCollector

# ---------------------------------------------------------------------------
# Timing Middleware
# ---------------------------------------------------------------------------


class TimingMiddleware(BaseHTTPMiddleware):
    """Add ``X-Response-Time`` header to all responses.

    Measures wall-clock time from request entry to response exit.
    """

    HEADER_NAME: str = "X-Response-Time"

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start) * 1000
        response.headers[self.HEADER_NAME] = f"{elapsed_ms:.2f}ms"
        # Also store on request state for downstream middleware
        request.state.response_time_ms = elapsed_ms
        return response


# ---------------------------------------------------------------------------
# Correlation ID Middleware
# ---------------------------------------------------------------------------


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Generate / propagate correlation ID for distributed request tracing.

    Flow:
        1. Check ``X-Correlation-ID`` header on incoming request.
        2. If absent, generate a new UUID4 correlation ID.
        3. Store in ``contextvars`` for access by loggers / services.
        4. Echo the ID back in the ``X-Correlation-ID`` response header.
    """

    HEADER_NAME: str = "X-Correlation-ID"

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        cid = request.headers.get(self.HEADER_NAME)
        if not cid:
            cid = str(uuid.uuid4())

        set_correlation_id(cid)
        request.state.correlation_id = cid

        response = await call_next(request)
        response.headers[self.HEADER_NAME] = cid
        return response


# ---------------------------------------------------------------------------
# Metrics Middleware
# ---------------------------------------------------------------------------


class MetricsMiddleware(BaseHTTPMiddleware):
    """Record request counts and durations in a :class:`MetricsCollector`.

    Labels recorded:
        * ``method`` -- HTTP method (GET, POST, ...)
        * ``endpoint`` -- route path template (``/api/v1/honeypots/{id}``)
        * ``status`` -- response status code (200, 404, 500, ...)
    """

    def __init__(
        self,
        app: Any,
        metrics_collector: MetricsCollector | None = None,
    ) -> None:
        super().__init__(app)
        self.collector = metrics_collector or MetricsCollector()

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        method = request.method
        endpoint = request.url.path

        start = time.perf_counter()
        try:
            response = await call_next(request)
            status = str(response.status_code)
        except Exception:
            status = "500"
            raise
        finally:
            elapsed = time.perf_counter() - start
            labels = {
                "method": method,
                "endpoint": endpoint,
                "status": status,
            }
            self.collector.observe(MetricsCollector.REQUEST_DURATION, elapsed, labels)
            self.collector.increment(MetricsCollector.REQUEST_COUNT, labels)

        return response


# ---------------------------------------------------------------------------
# Logging Middleware
# ---------------------------------------------------------------------------


class LoggingMiddleware(BaseHTTPMiddleware):
    """Log all HTTP requests with structured format.

    Logs at INFO for 2xx/3xx, WARNING for 4xx, ERROR for 5xx.
    Includes method, path, status, duration, and correlation ID.
    """

    def __init__(self, app: Any) -> None:
        super().__init__(app)
        self.logger = __import__("logging").getLogger("ember_honeypot.http")

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        start = time.perf_counter()
        cid = getattr(request.state, "correlation_id", get_correlation_id()) or "unknown"

        try:
            response = await call_next(request)
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            self.logger.error(
                f"{request.method} {request.url.path} -> exception",
                extra={
                    "extra": {
                        "method": request.method,
                        "path": str(request.url.path),
                        "duration_ms": round(elapsed, 2),
                        "correlation_id": cid,
                        "error": str(exc),
                    }
                },
            )
            raise

        elapsed = (time.perf_counter() - start) * 1000
        status = response.status_code
        level = "INFO" if status < 400 else "WARNING" if status < 500 else "ERROR"

        log_fn = (
            self.logger.info
            if level == "INFO"
            else self.logger.warning
            if level == "WARNING"
            else self.logger.error
        )
        log_fn(
            f"{request.method} {request.url.path} -> {status}",
            extra={
                "extra": {
                    "method": request.method,
                    "path": str(request.url.path),
                    "status": status,
                    "duration_ms": round(elapsed, 2),
                    "correlation_id": cid,
                }
            },
        )

        return response


# ---------------------------------------------------------------------------
# Combined middleware stack helper
# ---------------------------------------------------------------------------


def add_all_middleware(
    app: Any,
    metrics_collector: MetricsCollector | None = None,
) -> None:
    """Register all EmberHoneypot middleware on a FastAPI app.

    Order (outer -> inner):
        1. TimingMiddleware  -- measures total request time
        2. CorrelationIdMiddleware -- sets up tracing context
        3. LoggingMiddleware -- logs request/response
        4. MetricsMiddleware -- records prometheus metrics

    Args:
        app: FastAPI application instance.
        metrics_collector: Shared :class:`MetricsCollector` instance.
    """
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(MetricsMiddleware, metrics_collector=metrics_collector)
    app.add_middleware(CorrelationIdMiddleware)
    app.add_middleware(TimingMiddleware)
