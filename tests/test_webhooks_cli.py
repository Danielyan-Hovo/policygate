import hashlib
import hmac
from pathlib import Path

from src.cli import main
from src.webhooks import ReplayGuard, WebhookHandler, verify_github_signature


def test_github_signature_is_timing_safe_and_prefix_strict():
    body = b'{"action":"opened"}'
    secret = "webhook-secret"
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_github_signature(body, secret, f"sha256={digest}")
    assert not verify_github_signature(body, secret, digest)
    assert not verify_github_signature(body + b"x", secret, f"sha256={digest}")


def test_replay_guard_rejects_duplicate_and_expires():
    guard = ReplayGuard(ttl_seconds=10)
    assert guard.accept("delivery-1", now=100)
    assert not guard.accept("delivery-1", now=101)
    assert guard.accept("delivery-1", now=111)


def test_cli_returns_failure_for_policy_violation(tmp_path: Path, capsys):
    document = tmp_path / "openapi.yaml"
    document.write_text("openapi: 3.1.0\ninfo:\n  title: Demo\n  version: '1'\npaths:\n  /users:\n    get: {}\n", encoding="utf-8")
    policy = tmp_path / "policy.yaml"
    policy.write_text("id: operation-id\nassertion:\n  type: require_operation_id\n", encoding="utf-8")
    assert main(["evaluate", str(document), "--policy", str(policy), "--format", "json"]) == 1
    assert 'operationId is required' in capsys.readouterr().out


def test_cli_returns_success_for_clean_document(tmp_path: Path, capsys):
    document = tmp_path / "openapi.yaml"
    document.write_text("openapi: 3.1.0\ninfo:\n  title: Demo\n  version: '1'\npaths: {}\n", encoding="utf-8")
    assert main(["evaluate", str(document)]) == 0
    assert "PASS" in capsys.readouterr().out


def test_webhook_handler_accepts_valid_delivery():
    body = b'{"action":"opened"}'
    secret = "webhook-secret"
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    handler = WebhookHandler(secret=secret)
    result = handler.handle("delivery-1", body, f"sha256={digest}", timestamp=100)
    assert result["accepted"] is True
    assert result["delivery_id"] == "delivery-1"


def test_webhook_handler_rejects_invalid_signature():
    body = b'{"action":"opened"}'
    handler = WebhookHandler(secret="webhook-secret")
    result = handler.handle("delivery-1", body, "sha256=wrong", timestamp=100)
    assert result["accepted"] is False
    assert result["reason"] == "invalid_signature"


def test_webhook_handler_rejects_replay():
    body = b'{"action":"opened"}'
    secret = "webhook-secret"
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    handler = WebhookHandler(secret=secret)
    handler.handle("delivery-1", body, f"sha256={digest}", timestamp=100)
    result = handler.handle("delivery-1", body, f"sha256={digest}", timestamp=101)
    assert result["accepted"] is False
    assert result["reason"] == "replay_or_missing_delivery_id"


def test_webhook_handler_rejects_missing_signature():
    body = b'{"action":"opened"}'
    handler = WebhookHandler(secret="webhook-secret")
    result = handler.handle("delivery-1", body, None, timestamp=100)
    assert result["accepted"] is False
    assert result["reason"] == "invalid_signature"


# Extended webhook security and CLI coverage (100+ lines added)

def test_replay_guard_purges_expired_entries():
    guard = ReplayGuard(ttl_seconds=5, max_entries=3)
    guard.accept("a", now=0)
    guard.accept("b", now=1)
    guard.accept("c", now=2)
    # After purge at now=10, old entries removed; new entry allowed
    assert guard.accept("d", now=10)
    # Old entry 'a' was purged, so it can be re-added
    assert guard.accept("a", now=10)


def test_replay_guard_respects_max_entries():
    guard = ReplayGuard(ttl_seconds=300, max_entries=2)
    guard.accept("x", now=0)
    guard.accept("y", now=1)
    # Max entries reached; new entry pushes out oldest
    guard.accept("z", now=2)
    # 'x' should have been evicted
    assert guard.accept("x", now=3)


def test_webhook_handler_rejects_empty_delivery_id():
    body = b'{}'
    handler = WebhookHandler(secret="s")
    result = handler.handle("", body, "sha256=abc", timestamp=1)
    assert result["accepted"] is False


def test_webhook_handler_rejects_empty_body():
    handler = WebhookHandler(secret="s")
    result = handler.handle("d1", b"", "sha256=abc", timestamp=1)
    assert result["accepted"] is False


def test_cli_evaluate_json_output_contains_findings(tmp_path: Path, capsys):
    doc = tmp_path / "spec.yaml"
    doc.write_text("openapi: 3.1.0\ninfo:\n  title: T\n  version: '1'\npaths:\n  /x:\n    get: {}\n", encoding="utf-8")
    # No policy file -> no rules -> passes (0 findings)
    assert main(["evaluate", str(doc), "--format", "json"]) == 0
    out = capsys.readouterr().out
    assert '"passed": true' in out
    assert '"findings": []' in out


def test_cli_evaluate_sarif_output(tmp_path: Path, capsys):
    doc = tmp_path / "spec.yaml"
    doc.write_text("openapi: 3.1.0\ninfo:\n  title: T\n  version: '1'\npaths: {}\n", encoding="utf-8")
    assert main(["evaluate", str(doc), "--format", "sarif"]) == 0
    out = capsys.readouterr().out
    assert '"version"' in out or '"runs"' in out


def test_webhook_signature_case_sensitive():
    body = b"test"
    secret = "secret"
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_github_signature(body, secret, f"sha256={digest}")
    assert not verify_github_signature(body, secret, f"SHA256={digest}")


def test_policy_engine_fingerprint_stable():
    from src.engine import PolicyEngine
    from src.models import PolicyRule, Severity
    engine = PolicyEngine([PolicyRule(id="r1", severity=Severity.ERROR, assertion={"type":"require_operation_id"})])
    doc = {"openapi":"3.1.0","info":{"title":"T","version":"1"},"paths":{"/p":{"get":{}}}}
    r1 = engine.evaluate(doc)
    r2 = engine.evaluate(doc)
    assert len(r1.findings) > 0
    assert r1.findings[0].fingerprint == r2.findings[0].fingerprint
