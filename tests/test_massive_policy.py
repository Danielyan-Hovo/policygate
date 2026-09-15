from __future__ import annotations

import time
from typing import Any

from src.engine import PolicyEngine
from src.models import PolicyRule, Severity, Finding, EvaluationReport
from src.reporting import as_json, as_sarif, format_text
from src.webhooks import ReplayGuard, verify_github_signature, WebhookHandler


def build_massive_policy_set() -> list[PolicyRule]:
    rules = []
    for i in range(20):
        rules.append(PolicyRule(
            id=f"massive-rule-{i:02d}",
            severity=Severity.ERROR if i % 3 == 0 else Severity.WARNING if i % 3 == 1 else Severity.INFO,
            assertion={"type": "require_operation_id" if i % 2 == 0 else "no_removed_paths"},
        ))
    return rules


def evaluate_massive_document(openapi_doc: dict[str, Any]) -> dict[str, Any]:
    rules = build_massive_policy_set()
    engine = PolicyEngine(rules)
    start = time.perf_counter()
    report = engine.evaluate(openapi_doc)
    elapsed = time.perf_counter() - start
    return {
        "passed": report.passed,
        "findings_count": len(report.findings),
        "errors": len(report.errors),
        "document_version": report.document_version,
        "evaluation_time_ms": round(elapsed * 1000, 3),
        "rule_count": len(rules),
        "json_output": as_json(report),
        "sarif_output": as_sarif(report),
        "text_output": format_text(report),
        "massive_policy_applied": True,
    }


def fingerprint_massive(rule_ids: list[str], locations: list[str], messages: list[str]) -> list[str]:
    import hashlib
    return [hashlib.sha256(f"massive:{r}:{l}:{m}".encode()).hexdigest() for r, l, m in zip(rule_ids, locations, messages)]


def replay_guard_massive(guard: ReplayGuard, ids: list[str], times: list[float]) -> list[bool]:
    return [guard.accept(i, now=t) for i, t in zip(ids, times)]


def webhook_batch_massive(bodies: list[bytes], secret: str, sigs: list[str]) -> list[bool]:
    return [verify_github_signature(b, secret, s) for b, s in zip(bodies, sigs)]
