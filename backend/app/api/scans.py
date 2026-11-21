"""API skanów. API samo nie skanuje: zleca pracę workerowi w sieci z celami."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select

from app.api.deps import DispatcherDep, RulebookDep, ScopeGuardDep, SessionDep
from app.api.schemas import ApprovalIn, ScanActionOut, ScanRunOut, TaskOut
from app.core.scope_guard import Intrusiveness
from app.iam.deps import AuditSinkDep, ensure, require
from app.iam.redaction import RedactingRoute
from app.iam.tokens import Principal
from app.models import ScanAction, ScanRun
from app.scans.service import ScanActionError, ScanService

router = APIRouter(prefix="/api", tags=["skany"], route_class=RedactingRoute)

# Zatwierdzenie akcji wymaga uprawnienia odpowiadającego jej poziomowi inwazyjności.
_APPROVE_BASE = "scan:approve:l2"
_APPROVE_BY_LEVEL = {
    Intrusiveness.INTRUSIVE: "scan:approve:l2",
    Intrusiveness.REDTEAM: "scan:approve:l3",
}


@router.get("/scans", response_model=list[ScanRunOut], dependencies=[Depends(require("scan:read"))])
def list_scans(
    session: SessionDep, limit: Annotated[int, Query(ge=1, le=100)] = 10
) -> list[ScanRunOut]:
    runs = session.scalars(select(ScanRun).order_by(ScanRun.started_at.desc()).limit(limit)).all()
    result = []
    for run in runs:
        actions = session.scalars(
            select(ScanAction)
            .where(ScanAction.scan_run_id == run.id)
            .order_by(ScanAction.created_at)
        ).all()
        out = ScanRunOut.model_validate(run)
        out.actions = [ScanActionOut.model_validate(a) for a in actions]
        result.append(out)
    return result


@router.post("/scans", response_model=TaskOut, status_code=status.HTTP_202_ACCEPTED)
def trigger_scan(
    dispatcher: DispatcherDep,
    principal: Annotated[Principal, Depends(require("scan:run"))],
) -> TaskOut:
    """Zleca skan zakresu. Co zostanie zeskanowane, wynika z reguł plannera i scope_guard."""
    return TaskOut(
        task_id=dispatcher.run_scan(principal.actor), detail="Skan zlecony workerowi skanów"
    )


@router.get(
    "/scan-actions",
    response_model=list[ScanActionOut],
    dependencies=[Depends(require("scan:read"))],
)
def list_scan_actions(
    session: SessionDep,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[ScanActionOut]:
    query = select(ScanAction)
    if status_filter:
        query = query.where(ScanAction.status == status_filter)
    rows = session.scalars(query.order_by(ScanAction.created_at.desc()).limit(limit)).all()
    return [ScanActionOut.model_validate(r) for r in rows]


def _awaiting(
    session: SessionDep,
    action_id: uuid.UUID,
    principal: Principal,
    request: Request,
    audit: AuditSinkDep,
) -> ScanAction:
    action = session.get(ScanAction, action_id)
    if action is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono akcji")
    if action.status != "awaiting_approval":
        raise HTTPException(status.HTTP_409_CONFLICT, "Ta akcja nie czeka na zatwierdzenie")
    level = Intrusiveness(action.intrusiveness)
    permission = _APPROVE_BY_LEVEL.get(level)
    if permission is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Tej akcji nie da się zatwierdzić")
    ensure(principal, permission, request, audit)
    return action


ApproverDep = Annotated[Principal, Depends(require(_APPROVE_BASE))]


@router.post(
    "/scan-actions/{action_id}/approve",
    response_model=TaskOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def approve_scan_action(
    action_id: uuid.UUID,
    payload: ApprovalIn,
    session: SessionDep,
    dispatcher: DispatcherDep,
    principal: ApproverDep,
    request: Request,
    audit: AuditSinkDep,
) -> TaskOut:
    """Zgoda człowieka na akcję inwazyjną (L2 albo L3, zależnie od uprawnień). Akcja i tak
    przejdzie przez scope_guard."""
    _awaiting(session, action_id, principal, request, audit)
    task_id = dispatcher.approve_action(action_id, principal.username, payload.reason)
    return TaskOut(task_id=task_id, detail="Zatwierdzona akcja zlecona workerowi skanów")


@router.post("/scan-actions/{action_id}/reject", response_model=ScanActionOut)
def reject_scan_action(
    action_id: uuid.UUID,
    payload: ApprovalIn,
    session: SessionDep,
    guard: ScopeGuardDep,
    rulebook: RulebookDep,
    principal: ApproverDep,
    request: Request,
    audit: AuditSinkDep,
) -> ScanActionOut:
    _awaiting(session, action_id, principal, request, audit)
    try:
        action = ScanService(session, guard, rulebook).reject(
            action_id, rejected_by=principal.username, reason=payload.reason
        )
    except ScanActionError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    return ScanActionOut.model_validate(action)
