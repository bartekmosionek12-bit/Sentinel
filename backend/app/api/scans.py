"""API skanów. API samo nie skanuje: zleca pracę workerowi w sieci z celami."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select

from app.api.deps import DispatcherDep, RulebookDep, ScopeGuardDep, SessionDep
from app.api.schemas import ApprovalIn, ScanActionOut, ScanRunOut, ScanTriggerIn, TaskOut
from app.models import ScanAction, ScanRun
from app.scans.service import ScanActionError, ScanService

router = APIRouter(prefix="/api", tags=["skany"])


@router.get("/scans", response_model=list[ScanRunOut])
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
def trigger_scan(payload: ScanTriggerIn, dispatcher: DispatcherDep) -> TaskOut:
    """Zleca skan zakresu. Co zostanie zeskanowane, wynika z reguł plannera i scope_guard."""
    return TaskOut(
        task_id=dispatcher.run_scan(payload.actor), detail="Skan zlecony workerowi skanów"
    )


@router.get("/scan-actions", response_model=list[ScanActionOut])
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


def _awaiting(session: SessionDep, action_id: uuid.UUID) -> ScanAction:
    action = session.get(ScanAction, action_id)
    if action is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono akcji")
    if action.status != "awaiting_approval":
        raise HTTPException(status.HTTP_409_CONFLICT, "Ta akcja nie czeka na zatwierdzenie")
    return action


@router.post(
    "/scan-actions/{action_id}/approve",
    response_model=TaskOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def approve_scan_action(
    action_id: uuid.UUID, payload: ApprovalIn, session: SessionDep, dispatcher: DispatcherDep
) -> TaskOut:
    """Zgoda człowieka na akcję inwazyjną. Akcja i tak przejdzie przez scope_guard."""
    _awaiting(session, action_id)
    task_id = dispatcher.approve_action(action_id, payload.actor, payload.reason)
    return TaskOut(task_id=task_id, detail="Zatwierdzona akcja zlecona workerowi skanów")


@router.post("/scan-actions/{action_id}/reject", response_model=ScanActionOut)
def reject_scan_action(
    action_id: uuid.UUID,
    payload: ApprovalIn,
    session: SessionDep,
    guard: ScopeGuardDep,
    rulebook: RulebookDep,
) -> ScanActionOut:
    _awaiting(session, action_id)
    try:
        action = ScanService(session, guard, rulebook).reject(
            action_id, rejected_by=payload.actor, reason=payload.reason
        )
    except ScanActionError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    return ScanActionOut.model_validate(action)
