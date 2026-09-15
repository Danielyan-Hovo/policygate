import pytest
from src.reporting_large import (
    generate_large_report,
    fingerprint_stable,
    build_large_policy_set,
    evaluate_large_document,
)
from src.models import PolicyRule, Severity


def test_fingerprint_stable():
    fp1 = fingerprint_stable("r1", "/paths/x/get", "msg")
    fp2 = fingerprint_stable("r1", "/paths/x/get", "msg")
    assert fp1 == fp2
    assert len(fp1) == 64


def test_build_large_policy_set_has_ten_rules():
    rules = build_large_policy_set()
    assert len(rules) == 10
    ids = {r.id for r in rules}
    assert "security-auth-required" in ids
    assert "lint-operation-id-required" in ids


def test_generate_large_report_with_empty_document():
    doc = {"openapi": "3.1.0", "info": {"title": "T", "version": "1"}, "paths": {}}
    rules = build_large_policy_set()
    report = generate_large_report(doc, rules)
    assert isinstance(report.passed, bool)
    assert isinstance(report.findings, list)


def test_evaluate_large_document_returns_all_formats():
    doc = {"openapi": "3.1.0", "info": {"title": "T", "version": "1"}, "paths": {"/users": {"get": {"operationId": "listUsers"}}}}
    result = evaluate_large_document(doc)
    assert "passed" in result
    assert "findings_count" in result
    assert "json_output" in result
    assert "sarif_output" in result
    assert "text_output" in result
    assert result["findings_count"] >= 0


def test_large_policy_set_severities():
    rules = build_large_policy_set()
    severities = {r.severity for r in rules}
    assert Severity.ERROR in severities
    assert Severity.WARNING in severities
    assert Severity.INFO in severities


def test_evaluate_large_document_with_violations():
    doc = {"openapi": "3.1.0", "info": {"title": "T", "version": "1"}, "paths": {"/users": {"get": {}}}}
    result = evaluate_large_document(doc)
    assert result["findings_count"] > 0
    assert result["errors"] > 0


def test_fingerprint_changes_with_different_input():
    fp1 = fingerprint_stable("r1", "/a", "m")
    fp2 = fingerprint_stable("r2", "/a", "m")
    assert fp1 != fp2
