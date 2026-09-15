from __future__ import annotations

import hashlib
import time
from typing import Any

from src.engine import PolicyEngine
from src.models import PolicyRule, Severity, Finding, EvaluationReport
from src.reporting import as_json, as_sarif, format_text


def generate_large_report(document: dict[str, Any], rules: list[PolicyRule]) -> EvaluationReport:
    engine = PolicyEngine(rules)
    return engine.evaluate(document)


def fingerprint_stable(rule_id: str, location: str, message: str) -> str:
    input_str = f"{rule_id}:{location}:{message}"
    return hashlib.sha256(input_str.encode("utf-8")).hexdigest()


def build_large_policy_set() -> list[PolicyRule]:
    return [
        PolicyRule(id="security-auth-required", severity=Severity.ERROR, assertion={"type":"require_auth"}),
        PolicyRule(id="security-no-http", severity=Severity.ERROR, assertion={"type":"forbid_http"}),
        PolicyRule(id="compatibility-no-removed-paths", severity=Severity.WARNING, assertion={"type":"no_removed_paths"}),
        PolicyRule(id="compatibility-no-removed-operations", severity=Severity.WARNING, assertion={"type":"no_removed_operations"}),
        PolicyRule(id="lint-operation-id-required", severity=Severity.ERROR, assertion={"type":"require_operation_id"}),
        PolicyRule(id="lint-tags-required", severity=Severity.WARNING, assertion={"type":"require_tags"}),
        PolicyRule(id="lint-response-coverage", severity=Severity.INFO, assertion={"type":"response_coverage"}),
        PolicyRule(id="security-pii-query-param", severity=Severity.ERROR, assertion={"type":"no_pii_in_query"}),
        PolicyRule(id="security-sensitive-url-param", severity=Severity.WARNING, assertion={"type":"no_sensitive_path_params"}),
        PolicyRule(id="security-tls-required", severity=Severity.ERROR, assertion={"type":"require_tls"}),
    ]


def evaluate_large_document(openapi_doc: dict[str, Any]) -> dict[str, Any]:
    rules = build_large_policy_set()
    report = generate_large_report(openapi_doc, rules)
    return {
        "passed": report.passed,
        "findings_count": len(report.findings),
        "errors": len(report.errors),
        "document_version": report.document_version,
        "json_output": as_json(report),
        "sarif_output": as_sarif(report),
        "text_output": format_text(report),
    }


def build_large_report_with_metrics(openapi_doc: dict[str, Any]) -> dict[str, Any]:
    rules = build_large_policy_set()
    start = time.perf_counter()
    result = evaluate_large_document(openapi_doc)
    elapsed = time.perf_counter() - start
    result["evaluation_time_ms"] = round(elapsed * 1000, 3)
    return result


def verify_webhook_batch(body_list: list[bytes], secret: str, signatures: list[str]) -> list[bool]:
    results = []
    for body, sig in zip(body_list, signatures):
        results.append(verify_github_signature(body, secret, sig))
    return results


def replay_guard_batch(guard: ReplayGuard, delivery_ids: list[str], timestamps: list[float]) -> list[bool]:
    return [guard.accept(did, now=ts) for did, ts in zip(delivery_ids, timestamps)]


def fingerprint_batch(rule_ids: list[str], locations: list[str], messages: list[str]) -> list[str]:
    return [hashlib.sha256(f"{r}:{l}:{m}".encode()).hexdigest() for r, l, m in zip(rule_ids, locations, messages)]


def build_extended_policy_set() -> list[PolicyRule]:
    base = build_large_policy_set()
    extra = [
        PolicyRule(id="security-rate-limit", severity=Severity.WARNING, assertion={"type":"rate_limit"}),
        PolicyRule(id="security-cors-policy", severity=Severity.INFO, assertion={"type":"cors_policy"}),
        PolicyRule(id="security-content-security", severity=Severity.INFO, assertion={"type":"content_security_policy"}),
        PolicyRule(id="security-xss-protection", severity=Severity.INFO, assertion={"type":"xss_protection"}),
        PolicyRule(id="security-frame-ancestors", severity=Severity.INFO, assertion={"type":"frame_ancestors"}),
    ]
    return base + extra
