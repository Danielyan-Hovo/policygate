from __future__ import annotations

from src.metrics_ops import MetricsCollector, record_evaluation_metrics


def test_metrics_collector_counters():
    collector = MetricsCollector()
    collector.increment("test", 3)
    collector.increment("test", 2)
    assert collector.counters["test"] == 5


def test_metrics_collector_gauge():
    collector = MetricsCollector()
    collector.set_gauge("g", 42.5)
    assert collector.gauges["g"] == 42.5


def test_metrics_collector_histogram():
    collector = MetricsCollector()
    collector.observe("h", 10.0)
    collector.observe("h", 20.0)
    summary = collector.summary()
    assert summary["histograms"]["h"]["count"] == 2
    assert summary["histograms"]["h"]["avg"] == 15.0


def test_record_evaluation_metrics():
    collector = MetricsCollector()
    record_evaluation_metrics(collector, 12.5, True, 0)
    assert collector.counters.get("policygate_evaluations_total") == 1
    assert collector.counters.get("policygate_evaluations_passed") == 1
    assert collector.gauges.get("policygate_findings_current") == 0.0
