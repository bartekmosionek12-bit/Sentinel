"""API agenta AI i testu bezpieczeństwa agenta (Etap 5, moduł 19).

Model niczego tu nie wykonuje: API zapisuje polecenie, a plan układa worker `agent`.
Zatwierdzenie wymaga `agent:task` (MFA) i dodatkowo uprawnienia do poziomu każdego
zatwierdzanego kroku (`scan:approve:l2`, `scan:approve:l3`). Rola `agent` nie ma żadnego
uprawnienia z tego pliku, w tym `agent_test:*`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from ipaddress import ip_network
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.agent.capability import CapabilityError
from app.agent.planner import Planner
from app.agent.service import AgentError, AgentService, create_capability
from app.agent.switch import is_killed
from app.agent_tests import signing
from app.agent_tests.gate import (
    GateError,
    config_ready,
    force,
    request_change,
)
from app.api.deps import DispatcherDep, ScopeGuardDep, SessionDep, SettingsDep
from app.api.schemas import OrmModel, TaskOut
from app.core.scope_guard import Intrusiveness, ScopeGuard, domain_matches
from app.iam.deps import AuditSinkDep, ensure, require
from app.iam.redaction import RedactingRoute
from app.iam.tokens import Principal
from app.models import (
    AgentCapability,
    AgentConfigVersion,
    AgentStep,
    AgentSwitch,
    AgentTask,
    AgentTestCaseResult,
    AgentTestRun,
    CredentialLease,
)
from app.runtime import agent_runtime_config

router = APIRouter(prefix="/api/agent", tags=["agent"], route_class=RedactingRoute)

_APPROVE_BY_LEVEL = {
    int(Intrusiveness.LIGHT): None,
    int(Intrusiveness.INTRUSIVE): "scan:approve:l2",
    int(Intrusiveness.REDTEAM): "scan:approve:l3",
}


# --- schematy --------------------------------------------------------------------


class CapabilityIn(BaseModel):
    tools: list[str] = Field(min_length=1, max_length=20)
    targets: list[str] = Field(min_length=1, max_length=50)
    max_level: int = Field(ge=1, le=3)
    windows: list[dict[str, Any]] = Field(default_factory=list, max_length=14)
    max_calls_per_task: int = Field(default=20, ge=1, le=200)
    max_calls_per_target: int = Field(default=5, ge=1, le=50)
    note: str = Field(min_length=3, max_length=2000)


class CapabilityOut(OrmModel):
    id: uuid.UUID
    version: int
    tools: list[str]
    targets: list[str]
    max_level: int
    windows: list[Any]
    max_calls_per_task: int
    max_calls_per_target: int
    active: bool
    note: str
    created_by: str
    created_at: datetime


class ConfigOut(OrmModel):
    id: uuid.UUID
    model: str
    prompt_version: str
    capability_version: int
    external_llm: bool
    state: str
    reason: str
    forced_by: str | None
    force_justification: str | None
    created_by: str
    created_at: datetime
    activated_at: datetime | None


class TaskIn(BaseModel):
    command: str = Field(min_length=3, max_length=4000)


class StepOut(OrmModel):
    id: uuid.UUID
    position: int
    tool: str
    target: str
    level: int
    params: dict[str, Any]
    reason: str
    source: str
    status: str
    decision: str | None
    decision_reason: str | None
    result: dict[str, Any]
    started_at: datetime | None
    finished_at: datetime | None


class AgentTaskOut(OrmModel):
    id: uuid.UUID
    command: str
    status: str
    capability_version: int | None
    config_version_id: uuid.UUID | None
    plan_source: str | None
    plan_model: str | None
    plan_problems: list[str]
    created_by: str
    approved_by: str | None
    approval_reason: str | None
    approved_at: datetime | None
    summary: dict[str, Any]
    created_at: datetime
    finished_at: datetime | None
    steps: list[StepOut] = Field(default_factory=list)


class TaskApproveIn(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)
    # Brak listy = wszystkie kroki czekające na decyzję.
    step_ids: list[uuid.UUID] | None = None


class ReasonIn(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)


class LeaseOut(OrmModel):
    id: uuid.UUID
    task_id: uuid.UUID | None
    step_id: uuid.UUID | None
    kind: str
    target: str
    principal: str
    serial: str
    ttl_seconds: int
    issued_by: str
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revoked_by: str | None


class StatusOut(BaseModel):
    killed: bool
    killed_by: str | None
    killed_reason: str | None
    killed_at: datetime | None
    capability: CapabilityOut | None
    config: ConfigOut | None
    pending: list[ConfigOut]
    last_test: dict[str, Any] | None


class TestRunIn(BaseModel):
    suite: str = Field(pattern="^(quick|full)$")


class TestRunOut(OrmModel):
    id: uuid.UUID
    config_version_id: uuid.UUID | None
    suite: str
    trigger: str
    requested_by: str
    status: str
    model_passed: int
    model_failed: int
    code_passed: int
    code_failed: int
    passed: bool | None
    result_sha256: str | None
    signature: str | None
    created_at: datetime
    finished_at: datetime | None
    signature_valid: bool | None = None


class CaseResultOut(OrmModel):
    id: uuid.UUID
    case_id: str
    category: str
    title: str
    model_resisted: bool
    code_held: bool
    verdicts: list[Any]
    transcript: dict[str, Any]
    attempts: list[Any]


class TestRunDetailOut(TestRunOut):
    public_key: str | None
    cases: list[CaseResultOut] = Field(default_factory=list)


class ForceIn(BaseModel):
    justification: str = Field(min_length=20, max_length=4000)


# --- pomocnicze ------------------------------------------------------------------


def _service(
    session: SessionDep, guard: ScopeGuardDep, dispatcher: DispatcherDep, settings: SettingsDep
) -> AgentService:
    config = agent_runtime_config(settings)

    def enqueue(config_id: uuid.UUID) -> None:
        dispatcher.run_agent_test("quick", "config_change", "system:agent-config", config_id)

    return AgentService(
        session,
        guard,
        Planner(None),  # plan układa worker `agent`, nie API
        config_ready=lambda s: config_ready(s, config, enqueue),
    )


ServiceDep = Annotated[AgentService, Depends(_service)]


def _within_scope(guard: ScopeGuard, pattern: str) -> bool:
    config = guard.config
    try:
        network = ip_network(pattern, strict=False)
    except ValueError:
        domain = pattern.removeprefix("*.")
        return not any(domain_matches(domain, d) for d in config.denied_domains) and any(
            domain_matches(domain, d) for d in config.allowed_domains
        )
    return any(
        network.version == allowed.version and network.subnet_of(allowed)  # type: ignore[arg-type]
        for allowed in config.allowed_cidrs
    )


def _task_out(session: SessionDep, task: AgentTask) -> AgentTaskOut:
    out = AgentTaskOut.model_validate(task)
    out.steps = [
        StepOut.model_validate(s)
        for s in session.scalars(
            select(AgentStep).where(AgentStep.task_id == task.id).order_by(AgentStep.position)
        )
    ]
    return out


def _run_out(run: AgentTestRun, model: type[TestRunOut] = TestRunOut) -> TestRunOut:
    out = model.model_validate(run)
    if run.result_sha256 and run.signature and run.public_key:
        out.signature_valid = signing.verify(run.public_key, run.result_sha256, run.signature)
    return out


# --- stan, zdolności, kill switch ------------------------------------------------


@router.get("/status", response_model=StatusOut, dependencies=[Depends(require("agent:read"))])
def agent_status(session: SessionDep) -> StatusOut:
    switch = session.get(AgentSwitch, 1)
    capability = session.scalar(select(AgentCapability).where(AgentCapability.active.is_(True)))
    configs = session.scalars(
        select(AgentConfigVersion).order_by(AgentConfigVersion.created_at.desc())
    ).all()
    live = next((c for c in configs if c.state in ("active", "forced")), None)
    last = session.scalar(select(AgentTestRun).order_by(AgentTestRun.created_at.desc()).limit(1))
    return StatusOut(
        killed=is_killed(session),
        killed_by=switch.changed_by if switch and switch.killed else None,
        killed_reason=switch.reason if switch and switch.killed else None,
        killed_at=switch.changed_at if switch and switch.killed else None,
        capability=CapabilityOut.model_validate(capability) if capability else None,
        config=ConfigOut.model_validate(live) if live else None,
        pending=[ConfigOut.model_validate(c) for c in configs if c.state == "pending_test"],
        last_test=_run_out(last).model_dump(mode="json") if last else None,
    )


@router.get(
    "/capabilities",
    response_model=list[CapabilityOut],
    dependencies=[Depends(require("agent:read"))],
)
def list_capabilities(session: SessionDep) -> list[CapabilityOut]:
    rows = session.scalars(select(AgentCapability).order_by(AgentCapability.version.desc()))
    return [CapabilityOut.model_validate(r) for r in rows]


@router.post("/capabilities", response_model=ConfigOut, status_code=status.HTTP_201_CREATED)
def create_capabilities(
    payload: CapabilityIn,
    session: SessionDep,
    guard: ScopeGuardDep,
    dispatcher: DispatcherDep,
    settings: SettingsDep,
    principal: Annotated[Principal, Depends(require("agent:configure"))],
) -> ConfigOut:
    """Nowa wersja zdolności. Wchodzi w życie dopiero po zaliczonym teście agenta."""
    try:
        row = create_capability(
            session,
            actor=principal.actor,
            tools=payload.tools,
            targets=payload.targets,
            max_level=payload.max_level,
            windows=payload.windows,
            max_calls_per_task=payload.max_calls_per_task,
            max_calls_per_target=payload.max_calls_per_target,
            note=payload.note,
            scope_check=lambda target: _within_scope(guard, target),
        )
    except CapabilityError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(error)) from error
    config = request_change(
        session,
        agent_runtime_config(settings),
        capability_version=row.version,
        reason=f"Nowe zdolności v{row.version}: {payload.note}",
        actor=principal.actor,
    )
    session.commit()
    dispatcher.run_agent_test("quick", "config_change", principal.actor, config.id)
    return ConfigOut.model_validate(config)


@router.post("/kill", response_model=dict[str, Any])
def kill_agent(
    payload: ReasonIn,
    service: ServiceDep,
    principal: Annotated[Principal, Depends(require("agent:kill"))],
) -> dict[str, Any]:
    """Kill switch: agent przestaje działać od razu (MCP odrzuca wywołania, zadania stają)."""
    info = service.kill(actor=principal.actor, reason=payload.reason)
    return {
        **info,
        "detail": "Agent wyłączony. Włączy go dopiero nowa wersja zdolności po teście.",
    }


@router.get("/leases", response_model=list[LeaseOut], dependencies=[Depends(require("agent:read"))])
def list_leases(
    session: SessionDep, limit: Annotated[int, Query(ge=1, le=500)] = 100
) -> list[LeaseOut]:
    rows = session.scalars(
        select(CredentialLease).order_by(CredentialLease.issued_at.desc()).limit(limit)
    )
    return [LeaseOut.model_validate(r) for r in rows]


# --- zadania -----------------------------------------------------------------------


@router.get(
    "/tasks", response_model=list[AgentTaskOut], dependencies=[Depends(require("agent:read"))]
)
def list_tasks(
    session: SessionDep, limit: Annotated[int, Query(ge=1, le=100)] = 20
) -> list[AgentTaskOut]:
    rows = session.scalars(select(AgentTask).order_by(AgentTask.created_at.desc()).limit(limit))
    return [_task_out(session, t) for t in rows]


@router.get(
    "/tasks/{task_id}", response_model=AgentTaskOut, dependencies=[Depends(require("agent:read"))]
)
def get_task(task_id: uuid.UUID, session: SessionDep) -> AgentTaskOut:
    task = session.get(AgentTask, task_id)
    if task is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono zadania")
    return _task_out(session, task)


@router.post("/tasks", response_model=AgentTaskOut, status_code=status.HTTP_202_ACCEPTED)
def create_task(
    payload: TaskIn,
    session: SessionDep,
    service: ServiceDep,
    dispatcher: DispatcherDep,
    principal: Annotated[Principal, Depends(require("agent:task"))],
) -> AgentTaskOut:
    try:
        task = service.create_task(payload.command, actor=principal.actor)
    except AgentError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    dispatcher.plan_agent_task(task.id)
    return _task_out(session, task)


@router.post(
    "/tasks/{task_id}/approve", response_model=TaskOut, status_code=status.HTTP_202_ACCEPTED
)
def approve_task(
    task_id: uuid.UUID,
    payload: TaskApproveIn,
    service: ServiceDep,
    dispatcher: DispatcherDep,
    principal: Annotated[Principal, Depends(require("agent:task"))],
    request: Request,
    audit: AuditSinkDep,
) -> TaskOut:
    """Zgoda człowieka na wybrane kroki. L2/L3 wymagają też uprawnienia do poziomu."""

    def can(level: int) -> bool:
        permission = _APPROVE_BY_LEVEL.get(level, "scan:approve:l3")
        if permission is not None:
            ensure(principal, permission, request, audit)
        return True

    try:
        service.approve(
            task_id,
            actor=principal.actor,
            reason=payload.reason,
            step_ids=payload.step_ids,
            can_approve_level=can,
        )
    except AgentError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    job = dispatcher.execute_agent_task(task_id)
    return TaskOut(task_id=job, detail="Zatwierdzone kroki zlecone wykonawcy agenta")


@router.post("/tasks/{task_id}/reject", response_model=AgentTaskOut)
def reject_task(
    task_id: uuid.UUID,
    payload: ReasonIn,
    session: SessionDep,
    service: ServiceDep,
    principal: Annotated[Principal, Depends(require("agent:task"))],
) -> AgentTaskOut:
    try:
        task = service.reject(task_id, actor=principal.actor, reason=payload.reason)
    except AgentError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    return _task_out(session, task)


# --- moduł 19: test bezpieczeństwa agenta ------------------------------------------


@router.get(
    "/tests", response_model=list[TestRunOut], dependencies=[Depends(require("agent_test:read"))]
)
def list_tests(
    session: SessionDep, limit: Annotated[int, Query(ge=1, le=100)] = 20
) -> list[TestRunOut]:
    rows = session.scalars(
        select(AgentTestRun).order_by(AgentTestRun.created_at.desc()).limit(limit)
    )
    return [_run_out(r) for r in rows]


@router.get(
    "/tests/{run_id}",
    response_model=TestRunDetailOut,
    dependencies=[Depends(require("agent_test:read"))],
)
def get_test(run_id: uuid.UUID, session: SessionDep) -> TestRunOut:
    run = session.get(AgentTestRun, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono testu")
    out = TestRunDetailOut.model_validate(run)
    out.signature_valid = _run_out(run).signature_valid
    out.cases = [
        CaseResultOut.model_validate(c)
        for c in session.scalars(
            select(AgentTestCaseResult)
            .where(AgentTestCaseResult.run_id == run.id)
            .order_by(AgentTestCaseResult.case_id)
        )
    ]
    return out


@router.post("/tests", response_model=TaskOut, status_code=status.HTTP_202_ACCEPTED)
def run_agent_test(
    payload: TestRunIn,
    session: SessionDep,
    dispatcher: DispatcherDep,
    principal: Annotated[Principal, Depends(require("agent_test:run"))],
) -> TaskOut:
    """„Przetestuj bezpieczeństwo agenta”: zlecenie dla niezależnego harnessu."""
    pending = session.scalar(
        select(AgentConfigVersion)
        .where(AgentConfigVersion.state == "pending_test")
        .order_by(AgentConfigVersion.created_at.desc())
    )
    job = dispatcher.run_agent_test(
        payload.suite, "manual", principal.actor, pending.id if pending else None
    )
    return TaskOut(task_id=job, detail="Test zlecony niezależnemu harnessowi")


@router.post("/configs/{config_id}/force", response_model=ConfigOut)
def force_config(
    config_id: uuid.UUID,
    payload: ForceIn,
    session: SessionDep,
    principal: Annotated[Principal, Depends(require("agent_test:override"))],
) -> ConfigOut:
    """Świadome wymuszenie wersji mimo testu: uzasadnienie trafia do audytu i raportu."""
    try:
        config = force(
            session, config_id, actor=principal.actor, justification=payload.justification
        )
    except GateError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    return ConfigOut.model_validate(config)
