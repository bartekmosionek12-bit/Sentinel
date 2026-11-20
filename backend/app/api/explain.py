"""API wyjaśnień: odczyt z cache, zlecenie generowania i strumień postępu (SSE).

API nie wywołuje modelu. Generowanie zleca workerowi kolejki `llm`, a tekst pokazuje
z cache albo z szablonu.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable, Iterator
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import DispatcherDep, SessionDep, SettingsDep
from app.explainer.providers import ProviderHealth
from app.explainer.service import ExplainerService, Explanation, asset_header
from app.explainer.stream import START_ID, TERMINAL, EventBus
from app.iam.deps import AuditSinkDep, ensure, require
from app.iam.redaction import RedactingRoute
from app.iam.tokens import Principal
from app.models import Finding, Vulnerability
from app.runtime import explainer_service, get_event_bus, local_provider

router = APIRouter(prefix="/api", route_class=RedactingRoute)

Audience = Literal["technical", "operational", "executive"]
STREAM_TIMEOUT_SECONDS = 600
EventBusDep = Annotated[EventBus, Depends(get_event_bus)]


class LlmStatusOut(BaseModel):
    enabled: bool
    available: bool
    model: str
    detail: str
    external_enabled: bool


class ExplanationOut(BaseModel):
    finding_id: uuid.UUID
    cve_id: str
    audience: Audience
    asset_context: str
    text: str
    source: Literal["model", "template"]
    label: str
    validation: str
    cached: bool
    model: str | None
    prompt_version: str
    created_at: datetime | None
    problems: list[str] = []


class ExplanationRequestIn(BaseModel):
    audience: Audience
    regenerate: bool = False
    provider: Literal["local", "external"] = "local"


class ExplanationJobOut(BaseModel):
    job_id: str | None
    detail: str
    explanation: ExplanationOut | None = None


def llm_health(settings: SettingsDep) -> ProviderHealth:
    provider = local_provider(settings)
    if provider is None:
        return ProviderHealth(False, "", "Model nie jest skonfigurowany (LLM_MODEL jest pusty)")
    return provider.health()


def get_explainer_factory() -> Callable[[Session], ExplainerService]:
    return explainer_service


HealthDep = Annotated[ProviderHealth, Depends(llm_health)]
ExplainerDep = Annotated[Callable[[Session], ExplainerService], Depends(get_explainer_factory)]


def _finding_with_cve(session: Session, finding_id: uuid.UUID) -> tuple[Finding, Vulnerability]:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono findingu")
    vuln = (
        session.get(Vulnerability, finding.vulnerability_id) if finding.vulnerability_id else None
    )
    if vuln is None:
        raise HTTPException(
            422,
            "Wyjaśnienia są dostępne dla zagrożeń powiązanych z CVE",
        )
    return finding, vuln


def _out(session: Session, finding: Finding, explanation: Explanation) -> ExplanationOut:
    return ExplanationOut(
        finding_id=finding.id,
        cve_id=explanation.cve_id,
        audience=explanation.audience,
        asset_context=asset_header(session, finding),
        text=explanation.text,
        source=explanation.source,
        label=explanation.label,
        validation=explanation.validation,
        cached=explanation.cached,
        model=explanation.model if explanation.source == "model" else None,
        prompt_version=explanation.prompt_version,
        created_at=explanation.created_at,
        problems=list(explanation.problems),
    )


@router.get(
    "/llm/status",
    response_model=LlmStatusOut,
    tags=["wyjaśnienia"],
    dependencies=[Depends(require("findings:read"))],
)
def llm_status(settings: SettingsDep, health: HealthDep) -> LlmStatusOut:
    return LlmStatusOut(
        enabled=bool(settings.llm_model.strip()),
        available=health.available,
        model=health.model,
        detail=health.detail,
        external_enabled=settings.external_llm_enabled,
    )


@router.get(
    "/findings/{finding_id}/explanation",
    response_model=ExplanationOut,
    tags=["wyjaśnienia"],
    dependencies=[Depends(require("findings:read"))],
)
def get_explanation(
    finding_id: uuid.UUID,
    session: SessionDep,
    explainer: ExplainerDep,
    audience: Audience = "operational",
) -> ExplanationOut:
    """Tekst z cache albo z szablonu. To wywołanie nigdy nie uruchamia modelu."""
    finding, vuln = _finding_with_cve(session, finding_id)
    return _out(session, finding, explainer(session).get(vuln, audience))


@router.post(
    "/findings/{finding_id}/explanation",
    response_model=ExplanationJobOut,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["wyjaśnienia"],
)
def request_explanation(
    finding_id: uuid.UUID,
    payload: ExplanationRequestIn,
    session: SessionDep,
    settings: SettingsDep,
    dispatcher: DispatcherDep,
    bus: EventBusDep,
    health: HealthDep,
    explainer: ExplainerDep,
    principal: Annotated[Principal, Depends(require("explanations:generate"))],
    request: Request,
    audit: AuditSinkDep,
) -> ExplanationJobOut:
    """Zleca wygenerowanie wyjaśnienia. Gotowy tekst z cache wraca od razu, bez modelu."""
    finding, vuln = _finding_with_cve(session, finding_id)
    current = explainer(session).get(vuln, payload.audience)
    if current.cached and not payload.regenerate:
        return ExplanationJobOut(
            job_id=None,
            detail="Wyjaśnienie jest już w cache; model nie został wywołany",
            explanation=_out(session, finding, current),
        )
    use_external = payload.provider == "external"
    if use_external:
        ensure(principal, "llm:external:use", request, audit)
    if use_external and not settings.external_llm_enabled:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Zewnętrzny model jest wyłączony. Może go włączyć tylko administrator "
            "(EXTERNAL_LLM_ENABLED w pliku .env).",
        )
    if not use_external and not health.available:
        return ExplanationJobOut(
            job_id=None,
            detail=f"{health.detail}. Pokazuję wersję automatyczną z szablonu.",
            explanation=_out(session, finding, current),
        )
    job_id = uuid.uuid4().hex
    bus.publish(job_id, {"type": "queued"})
    dispatcher.generate_explanation(
        vuln.cve_id,
        payload.audience,
        principal.actor,
        job_id,
        regenerate=payload.regenerate,
        use_external=use_external,
    )
    return ExplanationJobOut(job_id=job_id, detail="Zlecono wygenerowanie wyjaśnienia")


def _sse(bus: EventBus, job_id: str, timeout: float, block_ms: int) -> Iterator[str]:
    last_id = START_ID
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        events = bus.read(job_id, last_id, block_ms=block_ms)
        if not events:
            yield ": czekam\n\n"  # komentarz SSE, utrzymuje połączenie
            continue
        for event_id, event in events:
            last_id = event_id
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
            if event.get("type") in TERMINAL:
                return
    yield 'data: {"type": "error", "message": "Przekroczono czas oczekiwania na model"}\n\n'


@router.get(
    "/explanations/jobs/{job_id}/events",
    tags=["wyjaśnienia"],
    dependencies=[Depends(require("findings:read"))],
)
def explanation_events(
    job_id: str,
    bus: EventBusDep,
) -> StreamingResponse:
    """Strumień zdarzeń (SSE): `queued`, `start`, `token`, `retry`, a na końcu `done` albo
    `error`. Tokeny są podglądem; obowiązuje tekst pobrany po `done`, już po walidacji."""
    if len(job_id) != 32 or any(ch not in "0123456789abcdef" for ch in job_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nieznane zadanie")
    return StreamingResponse(
        _sse(bus, job_id, STREAM_TIMEOUT_SECONDS, 1000),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
