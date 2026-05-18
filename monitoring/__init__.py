"""
SecureNet Monitoring & Observability Package.

Provides health checks, Prometheus metrics, structured logging,
FastAPI middleware, request tracing, and alerting for the
SecureNet intelligence platform.

Quick-start::

    from secure_net.monitoring import (
        HealthChecker, HealthStatus,
        MetricsCollector,
        configure_logging, get_logger,
        Tracer,
        add_all_middleware,
    )

    # 1. Configure logging
    configure_logging(level="INFO", json_format=True)

    # 2. Create health checker
    checker = HealthChecker(version="0.1.0")
    health = await checker.check(depth="shallow")

    # 3. Create metrics collector
    metrics = MetricsCollector()
    metrics.increment(MetricsCollector.INTERACTIONS_TOTAL, labels={"type": "ssh"})

    # 4. Set up tracing
    tracer = Tracer()
    with tracer.trace("server_session", session="abc-123"):
        ...
"""

from __future__ import annotations

from .health import ComponentHealth, HealthChecker, HealthStatus, Status
from .logging_config import (
    HumanReadableFormatter,
    StructuredLogFormatter,
    configure_logging,
    get_correlation_id,
    get_logger,
    set_correlation_id,
)
from .metrics import MetricsCollector
from .middleware import (
    CorrelationIdMiddleware,
    LoggingMiddleware,
    MetricsMiddleware,
    TimingMiddleware,
    add_all_middleware,
)
from .tracing import Tracer

__all__ = [
    # Health
    "HealthChecker",
    "HealthStatus",
    "ComponentHealth",
    "Status",
    # Metrics
    "MetricsCollector",
    # Logging
    "configure_logging",
    "get_logger",
    "StructuredLogFormatter",
    "HumanReadableFormatter",
    "get_correlation_id",
    "set_correlation_id",
    # Middleware
    "TimingMiddleware",
    "CorrelationIdMiddleware",
    "MetricsMiddleware",
    "LoggingMiddleware",
    "add_all_middleware",
    # Tracing
    "Tracer",
]

__version__ = "1.0.0"
