from src.compatibility import compare_documents, security_findings
from src.models import Severity


def document():
    return {
        "openapi": "3.1.0",
        "info": {"title": "Demo", "version": "1"},
        "servers": [{"url": "https://api.example.com"}],
        "security": [{"bearerAuth": []}],
        "paths": {"/users": {"get": {"operationId": "listUsers", "security": [{"bearerAuth": []}]}}},
    }


def test_compare_documents_detects_removed_path_and_operation():
    base = document()
    proposed = document()
    proposed["paths"] = {"/users": {}}
    findings = compare_documents(base, proposed)
    assert {finding.rule_id for finding in findings} == {"breaking.operation_removed"}

    proposed["paths"] = {}
    assert compare_documents(base, proposed)[0].rule_id == "breaking.path_removed"


def test_security_rules_detect_http_and_missing_auth():
    value = document()
    value["servers"] = [{"url": "http://api.example.com"}]
    value["security"] = []
    value["paths"]["/users"]["get"].pop("security")
    findings = security_findings(value)
    assert {finding.rule_id for finding in findings} == {"security.insecure_server", "security.auth_required"}
    assert all(finding.severity == Severity.ERROR for finding in findings)


def test_security_rule_detects_sensitive_url_parameter():
    value = document()
    value["paths"]["/users"]["get"]["parameters"] = [{"name": "email", "in": "query"}]
    assert security_findings(value)[0].rule_id == "security.sensitive_parameter"
