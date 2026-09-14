from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .engine import PolicyEngine
from .models import EvaluationReport, PolicyRule
from .parser import DocumentError
from .reporting import as_json, as_sarif, format_text


class EvaluationRequest(BaseModel):
    document: dict[str, Any]
    rules: list[PolicyRule] = Field(default_factory=list)


def create_app() -> FastAPI:
    app = FastAPI(title="PolicyGate", version="0.1.0")

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/evaluate", response_model=EvaluationReport)
    async def evaluate(request: EvaluationRequest) -> EvaluationReport:
        try:
            return PolicyEngine(request.rules).evaluate(request.document)
        except DocumentError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/v1/evaluate/text")
    async def evaluate_text(request: EvaluationRequest) -> dict[str, str]:
        try:
            report = PolicyEngine(request.rules).evaluate(request.document)
        except DocumentError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"report": format_text(report)}

    @app.post("/v1/evaluate/sarif")
    async def evaluate_sarif(request: EvaluationRequest) -> dict[str, Any]:
        try:
            report = PolicyEngine(request.rules).evaluate(request.document)
        except DocumentError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return as_sarif(report)

    @app.get("/healthz/details")
    async def health_details() -> dict[str, str | bool]:
        return {"status": "ok", "deterministic_engine": True, "advisory_ai": False}

    return app


app = create_app()
