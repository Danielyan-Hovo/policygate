from fastapi.testclient import TestClient

from src.api import create_app
from src.models import PolicyRule
from src.reporting import as_sarif, format_text
from src.engine import PolicyEngine


DOCUMENT = {
    "openapi": "3.1.0",
    "info": {"title": "Demo", "version": "1"},
    "paths": {"/users": {"get": {}}},
}
RULE = {"id": "operation-id", "assertion": {"type": "require_operation_id"}}


def test_json_sarif_and_text_reporting():
    report = PolicyEngine([PolicyRule(**RULE)]).evaluate(DOCUMENT)
    assert report.passed is False
    assert as_sarif(report)["version"] == "2.1.0"
    assert "FAIL" in format_text(report)


def test_api_returns_evaluation_report():
    client = TestClient(create_app())
    response = client.post("/v1/evaluate", json={"document": DOCUMENT, "rules": [RULE]})
    assert response.status_code == 200
    assert response.json()["passed"] is False


def test_api_returns_sarif_and_text_variants():
    client = TestClient(create_app())
    payload = {"document": DOCUMENT, "rules": [RULE]}
    assert client.post("/v1/evaluate/text", json=payload).json()["report"].startswith("PolicyGate: FAIL")
    assert client.post("/v1/evaluate/sarif", json=payload).json()["version"] == "2.1.0"


def test_api_rejects_invalid_openapi():
    client = TestClient(create_app())
    response = client.post("/v1/evaluate", json={"document": {"openapi": "3.2.0"}})
    assert response.status_code == 422
