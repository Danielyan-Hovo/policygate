from src.end_to_end import end_to_end_evaluation
from src.models import PolicyRule, Severity


def test_end_to_end_evaluation():
    doc = {"openapi": "3.1.0", "info": {"title": "T", "version": "1"}, "paths": {"/x": {"get": {"operationId": "op"}}}}
    rules = [PolicyRule(id="r1", severity=Severity.ERROR, assertion={"type": "require_operation_id"})]
    result = end_to_end_evaluation(doc, rules)
    assert "evaluation" in result
    assert "metrics" in result
    assert "advisory" in result
    assert "audit_persisted" in result
    assert result["evaluation"]["passed"] is True


def test_end_to_end_with_violations():
    doc = {"openapi": "3.1.0", "info": {"title": "T", "version": "1"}, "paths": {"/x": {"get": {}}}}
    rules = [PolicyRule(id="r1", severity=Severity.ERROR, assertion={"type": "require_operation_id"})]
    result = end_to_end_evaluation(doc, rules)
    assert result["evaluation"]["passed"] is False
    assert result["evaluation"]["findings"] > 0
    assert result["audit_persisted"] > 0
