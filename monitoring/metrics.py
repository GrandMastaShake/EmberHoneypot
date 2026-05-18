"""
Prometheus Metrics Collector for SecureNet.

Implements a lightweight, dependency-free Prometheus metrics exporter.
Supports counters, gauges, histograms, and timing context managers.

Usage:
    collector = MetricsCollector()
    collector.increment(MetricsCollector.INTERACTIONS_TOTAL, labels={"type": "ssh"})
    with collector.timer(MetricsCollector.INTERACTION_DURATION):
        handle_interaction()
    print(collector.export_prometheus())
"""

from __future__ import annotations

import statistics
import time
from collections import defaultdict
from contextlib import contextmanager
from typing import Any, Generator




class MetricsCollector:
    """Collects and exposes Prometheus-format metrics.

    All metric names follow the ``securenet_<subsystem>_<unit>`` convention.
    No external library dependencies are required.

    Example:
        >>> m = MetricsCollector()
        >>> m.increment("securenet_interactions_total", labels={"type": "ssh"})
        >>> m.export_prometheus()
        '# HELP securenet_interactions_total ...\\n...'
    """

    # ------------------------------------------------------------------
    # Pre-defined metric names
    # ------------------------------------------------------------------

    INTERACTIONS_TOTAL: str = "securenet_interactions_total"
    INTERACTION_DURATION: str = "securenet_interaction_duration_seconds"
    UNIQUE_ATTACKERS: str = "securenet_unique_attackers"
    ATTACKS_BLOCKED: str = "securenet_attacks_blocked_total"
    TTP_EXTRACTED: str = "securenet_ttp_extracted_total"
    FEEDS_PUBLISHED: str = "securenet_feeds_published_total"
    PERSONAS_ACTIVE: str = "securenet_personas_active"
    DECEPTION_SUCCESS_RATE: str = "securenet_deception_success_rate"
    INSTANCES_TOTAL: str = "securenet_instances_total"
    ENGINE_RUNNING: str = "securenet_engine_running"
    REQUEST_DURATION: str = "securenet_request_duration_seconds"
    REQUEST_COUNT: str = "securenet_request_count_total"

    # Default histogram buckets (in seconds) -- aligns with Prometheus defaults
    DEFAULT_BUCKETS: tuple[float, ...] = (
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, float("inf"),
    )

    def __init__(self) -> None:
        self._counters: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._gauges: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._histograms: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self._timers: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self._help_text: dict[str, str] = {
            self.INTERACTIONS_TOTAL: "Total attacker interactions",
            self.INTERACTION_DURATION: "Interaction handling duration in seconds",
            self.UNIQUE_ATTACKERS: "Unique attacker IPs observed",
            self.ATTACKS_BLOCKED: "Total attacks that hit the server",
            self.TTP_EXTRACTED: "TTPs extracted from attacker sessions",
            self.FEEDS_PUBLISHED: "Intel feeds published to swarm",
            self.PERSONAS_ACTIVE: "Active deception personas",
            self.DECEPTION_SUCCESS_RATE: "Percentage of attackers successfully deceived",
            self.INSTANCES_TOTAL: "Total server instances managed",
            self.ENGINE_RUNNING: "Engine running status (1=running)",
            self.REQUEST_DURATION: "HTTP request duration in seconds",
            self.REQUEST_COUNT: "Total HTTP request count",
        }
        self._buckets: dict[str, tuple[float, ...]] = defaultdict(
            lambda: self.DEFAULT_BUCKETS
        )

    # ------------------------------------------------------------------
    # Counters
    # ------------------------------------------------------------------

    def increment(
        self, name: str, labels: dict[str, str] | None = None, value: int = 1
    ) -> None:
        """Increment a counter metric.

        Args:
            name: Metric name (e.g. ``securenet_interactions_total``).
            labels: Label dict (serialised to ``key="val",...``).
            value: Amount to increment (default 1). Counters must be
                monotonically non-decreasing.
        """
        label_key = self._labels_to_key(labels or {})
        self._counters[name][label_key] += value

    # ------------------------------------------------------------------
    # Gauges
    # ------------------------------------------------------------------

    def gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        """Set a gauge value.

        Args:
            name: Metric name (e.g. ``securenet_personas_active``).
            value: Current gauge value (can go up or down).
            labels: Label dict.
        """
        label_key = self._labels_to_key(labels or {})
        self._gauges[name][label_key] = value

    def gauge_inc(
        self, name: str, labels: dict[str, str] | None = None, value: float = 1.0
    ) -> None:
        """Increment a gauge by *value*."""
        label_key = self._labels_to_key(labels or {})
        self._gauges[name][label_key] += value

    def gauge_dec(
        self, name: str, labels: dict[str, str] | None = None, value: float = 1.0
    ) -> None:
        """Decrement a gauge by *value*."""
        label_key = self._labels_to_key(labels or {})
        self._gauges[name][label_key] -= value

    # ------------------------------------------------------------------
    # Histograms / Timing
    # ------------------------------------------------------------------

    def observe(
        self, name: str, value: float, labels: dict[str, str] | None = None
    ) -> None:
        """Record an observation into a histogram.

        Args:
            name: Metric name (e.g. ``securenet_interaction_duration_seconds``).
            value: Observed value (seconds for durations).
            labels: Label dict.
        """
        label_key = self._labels_to_key(labels or {})
        self._histograms[name][label_key].append(value)

    @contextmanager
    def timer(
        self, name: str, labels: dict[str, str] | None = None
    ) -> Generator[None, None, None]:
        """Context manager for timing operations.

        Usage::

            with collector.timer(MetricsCollector.INTERACTION_DURATION):
                handle_interaction()
        """
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - start
            self.observe(name, elapsed, labels)

    # ------------------------------------------------------------------
    # Prometheus export
    # ------------------------------------------------------------------

    def export_prometheus(self) -> str:
        """Export all metrics in Prometheus text format (0.0.4).

        Returns:
            Multi-line string compatible with Prometheus scrape protocol.
        """
        lines: list[str] = []

        # Counters
        for name, label_map in self._counters.items():
            lines.extend(self._render_counter(name, label_map))

        # Gauges
        for name, label_map in self._gauges.items():
            lines.extend(self._render_gauge(name, label_map))

        # Histograms (include _count, _sum, and _bucket)
        for name, label_map in self._histograms.items():
            lines.extend(self._render_histogram(name, label_map))

        # Timers are stored as histograms -- merge them in
        for name, label_map in self._timers.items():
            if name not in self._histograms:
                lines.extend(self._render_histogram(name, label_map))

        return "\n".join(lines) + "\n" if lines else ""

    # ------------------------------------------------------------------
    # Snapshot for programmatic access
    # ------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serialisable snapshot of all metrics.

        Useful for health-check endpoints or debug panels.
        """
        return {
            "counters": {k: dict(v) for k, v in self._counters.items()},
            "gauges": {k: dict(v) for k, v in self._gauges.items()},
            "histograms": {
                k: {
                    lk: {
                        "count": len(lv),
                        "sum": round(sum(lv), 4),
                        "avg": round(statistics.mean(lv), 4) if lv else 0,
                    }
                    for lk, lv in v.items()
                }
                for k, v in self._histograms.items()
            },
        }

    # ------------------------------------------------------------------
    # Render helpers
    # ------------------------------------------------------------------

    def _render_counter(self, name: str, label_map: dict[str, int]) -> list[str]:
        lines: list[str] = []
        help_text = self._help_text.get(name, f"Counter {name}")
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} counter")
        for label_key, value in sorted(label_map.items()):
            if label_key:
                lines.append(f'{name}{{{label_key}}} {value}')
            else:
                lines.append(f"{name} {value}")
        return lines

    def _render_gauge(self, name: str, label_map: dict[str, float]) -> list[str]:
        lines: list[str] = []
        help_text = self._help_text.get(name, f"Gauge {name}")
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} gauge")
        for label_key, value in sorted(label_map.items()):
            if label_key:
                lines.append(f'{name}{{{label_key}}} {value}')
            else:
                lines.append(f"{name} {value}")
        return lines

    def _render_histogram(
        self, name: str, label_map: dict[str, list[float]]
    ) -> list[str]:
        lines: list[str] = []
        help_text = self._help_text.get(name, f"Histogram {name}")
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} histogram")

        buckets = self._buckets[name]
        for label_key, values in sorted(label_map.items()):
            # _bucket lines
            for bucket in buckets:
                le = "+Inf" if bucket == float("inf") else str(bucket)
                count = sum(1 for v in values if v <= bucket)
                if label_key:
                    lines.append(f'{name}_bucket{{{label_key},le="{le}"}} {count}')
                else:
                    lines.append(f'{name}_bucket{{le="{le}"}} {count}')

            # _sum
            total = sum(values)
            if label_key:
                lines.append(f'{name}_sum{{{label_key}}} {total:.6f}')
            else:
                lines.append(f"{name}_sum {total:.6f}")

            # _count
            if label_key:
                lines.append(f'{name}_count{{{label_key}}} {len(values)}')
            else:
                lines.append(f"{name}_count {len(values)}")

        return lines

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _labels_to_key(labels: dict[str, str]) -> str:
        """Serialise a label dict to Prometheus label string.

        >>> MetricsCollector._labels_to_key({"method": "GET", "status": "200"})
        'method="GET",status="200"'
        """
        if not labels:
            return ""
        return ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
