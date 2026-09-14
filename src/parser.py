from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


class DocumentError(ValueError):
    """Raised when an API or policy document is unsafe or invalid."""


SUPPORTED_OPENAPI_VERSIONS = {"3.1.0", "3.1.1", "3.1.2"}


def load_document(source: str | Path, *, max_bytes: int = 2_000_000) -> dict[str, Any]:
    path = Path(source)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DocumentError(f"cannot read document: {path}") from exc
    if len(raw) > max_bytes:
        raise DocumentError(f"document exceeds {max_bytes} bytes")
    if not raw.strip():
        raise DocumentError("document is empty")
    try:
        value = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise DocumentError("document is not valid YAML") from exc
    if not isinstance(value, dict):
        raise DocumentError("document root must be an object")
    return value


def validate_openapi_document(document: dict[str, Any]) -> str:
    version = document.get("openapi")
    if not isinstance(version, str):
        raise DocumentError("document must declare an OpenAPI version")
    if version not in SUPPORTED_OPENAPI_VERSIONS:
        raise DocumentError(f"unsupported OpenAPI version: {version}")
    info = document.get("info")
    if not isinstance(info, dict) or not isinstance(info.get("title"), str):
        raise DocumentError("OpenAPI info.title is required")
    if not isinstance(info.get("version"), str):
        raise DocumentError("OpenAPI info.version is required")
    paths = document.get("paths")
    if paths is not None and not isinstance(paths, dict):
        raise DocumentError("OpenAPI paths must be an object")
    return version


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
