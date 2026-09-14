from __future__ import annotations

from typing import Any

from .models import Finding, PolicyRule, Severity
from .engine import PolicyEngine


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


def compare_documents(base: dict[str, Any], proposed: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    base_paths = base.get("paths") or {}
    new_paths = proposed.get("paths") or {}
    for path, base_item in base_paths.items():
        if path not in new_paths:
            findings.append(_finding("breaking.path_removed", "path was removed", f"/paths/{_pointer(path)}"))
            continue
        for method in base_item if isinstance(base_item, dict) else {}:
            if method.lower() in HTTP_METHODS and method not in new_paths[path]:
                location = f"/paths/{_pointer(path)}/{method}"
                findings.append(_finding("breaking.operation_removed", "operation was removed", location))
    return findings


def security_findings(document: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    servers = document.get("servers") or []
    for index, server in enumerate(servers):
        if isinstance(server, dict) and str(server.get("url", "")).startswith("http://"):
            findings.append(_finding("security.insecure_server", "server must use HTTPS", f"/servers/{index}/url", Severity.ERROR))
    for path, item in (document.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            if not operation.get("security") and not document.get("security"):
                findings.append(_finding("security.auth_required", "operation must declare authentication", f"/paths/{_pointer(path)}/{method}", Severity.ERROR))
            parameters = operation.get("parameters", [])
            for parameter in parameters:
                if isinstance(parameter, dict) and parameter.get("in") in {"query", "path"}:
                    name = str(parameter.get("name", "")).lower()
                    if any(token in name for token in ("email", "phone", "ssn", "token", "password")):
                        findings.append(_finding("security.sensitive_parameter", "sensitive data cannot be in URL parameters", f"/paths/{_pointer(path)}/{method}/parameters", Severity.ERROR))
    return findings


def _finding(rule_id: str, message: str, location: str, severity: Severity = Severity.ERROR) -> Finding:
    return PolicyEngine._finding(PolicyRule(id=rule_id, severity=severity), message, location)


def _pointer(value: str) -> str:
    return value.strip("/").replace("~", "~0").replace("/", "~1")
