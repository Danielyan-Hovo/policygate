from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Any

from .models import EvaluationReport, Finding, PolicyRule, Severity
from .parser import canonical_json, validate_openapi_document


class PolicyEngine:
    """Deterministic policy evaluator; advisory AI is intentionally outside this class."""

    def __init__(self, rules: Iterable[PolicyRule] = ()) -> None:
        self.rules = tuple(rules)

    def evaluate(self, document: dict[str, Any]) -> EvaluationReport:
        version = validate_openapi_document(document)
        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(self._evaluate_rule(rule, document))
        return EvaluationReport(
            document_version=version,
            findings=findings,
            passed=not any(finding.severity == Severity.ERROR for finding in findings),
        )

    def _evaluate_rule(self, rule: PolicyRule, document: dict[str, Any]) -> list[Finding]:
        assertion = rule.assertion
        if assertion.get("type") == "required_root_field":
            field = assertion.get("field")
            if field and field not in document:
                return [self._finding(rule, f"required root field is missing: {field}", f"/{field}")]
        if assertion.get("type") == "require_operation_id":
            return self._operation_id_findings(rule, document)
        return []

    def _operation_id_findings(self, rule: PolicyRule, document: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for path, path_item in (document.get("paths") or {}).items():
            if not isinstance(path_item, dict):
                continue
            for method, operation in path_item.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options", "trace"}:
                    continue
                if isinstance(operation, dict) and not operation.get("operationId"):
                    location = f"/paths/{path.strip('/').replace('/', '~1')}/{method}"
                    findings.append(self._finding(rule, "operationId is required", location))
        return findings

    @staticmethod
    def _finding(rule: PolicyRule, message: str, location: str) -> Finding:
        fingerprint_input = canonical_json({"rule": rule.id, "location": location, "message": message})
        fingerprint = hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()
        return Finding(
            rule_id=rule.id,
            rule_version=rule.version,
            severity=rule.severity,
            message=message,
            location=location,
            remediation=rule.description or None,
            fingerprint=fingerprint,
        )
