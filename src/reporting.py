from __future__ import annotations

from typing import Any

from .models import EvaluationReport, Finding


def as_json(report: EvaluationReport) -> dict[str, Any]:
    return report.model_dump(mode="json")


def as_sarif(report: EvaluationReport, tool_name: str = "PolicyGate") -> dict[str, Any]:
    results = []
    for finding in report.findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": "error" if finding.severity.value == "error" else "warning",
                "message": {"text": finding.message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.location}}}],
                "fingerprints": {"policygate/v1": finding.fingerprint},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool_name}}, "results": results}],
    }


def format_text(report: EvaluationReport) -> str:
    lines = [f"PolicyGate: {'PASS' if report.passed else 'FAIL'} (OpenAPI {report.document_version})"]
    for finding in report.findings:
        lines.append(f"[{finding.severity.value}] {finding.rule_id} {finding.location}: {finding.message}")
    return "\n".join(lines)
