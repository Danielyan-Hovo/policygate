from __future__ import annotations

import time
from typing import Any


class MetricsCollector:
    """Phase 5: Low-cardinality Prometheus-style metrics for PolicyGate."""

    def __init__(self) -> None:
        self.counters: dict[str, int] = {}
        self.gauges: dict[str, float] = {}
        self.histograms: dict[str, list[float]] = {}

    def increment(self, name: str, value: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + value

    def set_gauge(self, name: str, value: float) -> None:
        self.gauges[name] = value

    def observe(self, name: str, value: float) -> None:
        self.histograms.setdefault(name, []).append(value)

    def summary(self) -> dict[str, Any]:
        hist_summary = {}
        for name, values in self.histograms.items():
            hist_summary[name] = {
                "count": len(values),
                "sum": sum(values),
                "avg": sum(values) / len(values) if values else 0.0,
                "min": min(values) if values else 0.0,
                "max": max(values) if values else 0.0,
            }
        return {
            "counters": self.counters.copy(),
            "gauges": self.gauges.copy(),
            "histograms": hist_summary,
        }


def record_evaluation_metrics(collector: MetricsCollector, duration_ms: float, passed: bool, findings: int) -> None:
    collector.increment("policygate_evaluations_total")
    collector.increment("policygate_evaluations_passed" if passed else "policygate_evaluations_failed")
    collector.observe("policygate_evaluation_duration_ms", duration_ms)
    collector.set_gauge("policygate_findings_current", float(findings))
