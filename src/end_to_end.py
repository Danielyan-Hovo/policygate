from __future__ import annotations

import json
from typing import Any

from src.advisory import AdvisoryEngine
from src.metrics_ops import MetricsCollector, record_evaluation_metrics
from src.persistence import AuditStorage
from src.engine import PolicyEngine
from src.models import PolicyRule, Severity


def end_to_end_evaluation(openapi_doc: dict[str, Any], rules: list[PolicyRule]) -> dict[str, Any]:
    collector = MetricsCollector()
    engine = PolicyEngine(rules)
    import time
    start = time.perf_counter()
    report = engine.evaluate(openapi_doc)
    duration = (time.perf_counter() - start) * 1000
    record_evaluation_metrics(collector, duration, report.passed, len(report.findings))
    advisory = AdvisoryEngine({"r1": "Add authentication to secure endpoint"})
    explained = advisory.explain_findings([{"rule_id": f.rule_id, "message": f.message, "location": f.location, "severity": f.severity.value} for f in report.findings])
    storage = AuditStorage(":memory:")
    for finding in report.findings:
        storage.persist({
            "fingerprint": finding.fingerprint,
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "message": finding.message,
            "location": finding.location,
            "evidence": finding.evidence,
        })
    return {
        "evaluation": {
            "passed": report.passed,
            "findings": len(report.findings),
            "errors": len(report.errors),
            "duration_ms": round(duration, 3),
        },
        "metrics": collector.summary(),
        "advisory": explained,
        "audit_persisted": len(report.findings),
    }
