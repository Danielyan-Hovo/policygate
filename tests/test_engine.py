from pathlib import Path

import pytest

from src.engine import PolicyEngine
from src.models import PolicyRule, Severity
from src.parser import DocumentError, load_document, validate_openapi_document


VALID = {
    "openapi": "3.1.0",
    "info": {"title": "Demo API", "version": "1.0.0"},
    "paths": {"/users": {"get": {"operationId": "listUsers"}}},
}


def test_engine_passes_valid_document():
    report = PolicyEngine().evaluate(VALID)
    assert report.passed is True
    assert report.findings == []


def test_operation_id_rule_is_deterministic():
    document = {**VALID, "paths": {"/users": {"get": {}}}}
    rule = PolicyRule(id="operation-id", description="Add operation IDs", assertion={"type": "require_operation_id"})
    first = PolicyEngine([rule]).evaluate(document)
    second = PolicyEngine([rule]).evaluate(document)
    assert first.passed is False
    assert first.model_dump() == second.model_dump()
    assert first.errors[0].location == "/paths/users/get"


def test_required_root_field_rule_can_warn():
    rule = PolicyRule(
        id="tags-required",
        severity=Severity.WARNING,
        assertion={"type": "required_root_field", "field": "tags"},
    )
    report = PolicyEngine([rule]).evaluate(VALID)
    assert report.passed is True
    assert report.findings[0].severity == Severity.WARNING


def test_parser_rejects_unsupported_version():
    with pytest.raises(DocumentError, match="unsupported"):
        validate_openapi_document({"openapi": "3.2.0", "info": {"title": "x", "version": "1"}})


def test_parser_rejects_large_or_invalid_root(tmp_path: Path):
    path = tmp_path / "bad.yaml"
    path.write_text("- value\n", encoding="utf-8")
    with pytest.raises(DocumentError, match="root"):
        load_document(path)

    huge = tmp_path / "huge.yaml"
    huge.write_text("x: " + "a" * 100, encoding="utf-8")
    with pytest.raises(DocumentError, match="exceeds"):
        load_document(huge, max_bytes=10)
