"""Zadania agenta: polecenie → plan → walidacja → zatwierdzenie → wykonanie przez kod.

Model tylko proponuje kroki. O tym, co się wykona, decydują kolejno: walidator planu (kod),
człowiek z rolą admin (MFA, L2/L3 wymaga osobnego uprawnienia) i serwer MCP (polityka,
`scope_guard`). Wykonawca wywołuje narzędzia wyłącznie przez bramę MCP.
"""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.agent.capability import Capability, CapabilityError
from app.agent.gateway import ToolGateway
from app.agent.planner import Plan, PlannedStep, Planner
from app.agent.switch import is_killed
from app.agent.validator import StepVerdict, validate_plan
from app.core import audit
from app.core.scope_guard import ScopeGuard
from app.mcp_server.runtime import ToolRequest, active_capability
from app.models import AgentCapability, AgentStep, AgentSwitch, AgentTask, Asset
from app.models.base import utcnow

ACTIVE_TASK_STATUSES = ("planning", "awaiting_approval", "approved", "running")
MAX_FOLLOW_UP_ROUNDS = 1


class AgentError(Exception):
    """Operacji na zadaniu nie da się wykonać (zły stan, brak uprawnień, kill switch)."""


class AgentService:
    def __init__(
        self,
        session: Session,
        guard: ScopeGuard,
        planner: Planner,
        *,
        templates_for: Callable[[str], Sequence[str]] | None = None,
        config_ready: Callable[[Session], tuple[uuid.UUID | None, str | None]] | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._session = session
        self._guard = guard
        self._planner = planner
        self._templates_for = templates_for
        # Bramka zmian (moduł 19): (id aktywnej wersji konfiguracji, powód blokady).
        self._config_ready = config_ready
        self._clock = clock

    # --- tworzenie i plan ------------------------------------------------------

    def create_task(self, command: str, *, actor: str) -> AgentTask:
        """Zapisuje polecenie. Plan układa osobne zadanie (`plan_task`) w workerze agenta."""
        session = self._session
        command = command.strip()
        if not command:
            raise AgentError("Polecenie jest puste")
        if is_killed(session):
            raise AgentError("Agent jest wyłączony (kill switch). Włączy go nowa wersja zdolności.")
        config_id: uuid.UUID | None = None
        if self._config_ready is not None:
            config_id, blocked = self._config_ready(session)
            if blocked:
                raise AgentError(blocked)
        capability = active_capability(session)
        if capability is None:
            raise AgentError("Agent nie ma aktywnych zdolności. Nada je administrator.")
        task = AgentTask(
            command=command[:4000],
            status="planning",
            capability_version=capability.version,
            config_version_id=config_id,
            created_by=actor,
        )
        session.add(task)
        session.flush()
        self._audit(
            actor, "agent_task_created", "Nowe zadanie dla agenta", task, {"command": command[:500]}
        )
        session.commit()
        return task

    def plan_task(self, task_id: uuid.UUID) -> AgentTask:
        session = self._session
        task = session.get(AgentTask, task_id)
        if task is None or task.status != "planning":
            raise AgentError("Zadanie nie czeka na plan")
        capability = active_capability(session)
        if capability is None or is_killed(session):
            task.status = "failed"
            task.finished_at = self._clock()
            task.summary = {"note": "Brak aktywnych zdolności albo agent wyłączony"}
            session.commit()
            return task
        plan = self._planner.plan(task.command, capability, self._known_hosts(capability))
        task.plan_source = plan.source
        task.plan_model = plan.model
        task.plan_problems = plan.problems[:20]
        verdicts = self._validate(task, plan.steps, capability, source="plan")
        self._save_steps(task, verdicts, "plan")
        self._after_plan(task, plan, verdicts, task.created_by)
        session.commit()
        return task

    def _known_hosts(self, capability: Capability) -> list[str]:
        hosts = []
        for asset in self._session.scalars(select(Asset).where(Asset.type == "host")):
            address = (asset.attributes or {}).get("address")
            if address and capability.covers_target(str(address)):
                hosts.append(str(address))
        return sorted(set(hosts))

    def _validate(
        self, task: AgentTask, steps: Sequence[PlannedStep], capability: Capability, *, source: str
    ) -> list[StepVerdict]:
        existing = list(
            self._session.scalars(select(AgentStep).where(AgentStep.task_id == task.id))
        )
        counted = [s for s in existing if s.status not in ("blocked", "skipped")]
        return validate_plan(
            steps,
            capability,
            self._guard,
            killed=is_killed(self._session),
            now=self._clock(),
            task_id=str(task.id),
            already=[(s.tool, s.target, dict(s.params or {})) for s in counted],
            calls_before=len(counted),
            target_calls_before=Counter(s.target for s in counted),
            templates_for=self._templates_for,
        )

    def _save_steps(self, task: AgentTask, verdicts: Sequence[StepVerdict], source: str) -> None:
        start = (
            self._session.scalar(
                select(func.max(AgentStep.position)).where(AgentStep.task_id == task.id)
            )
            or 0
        )
        for offset, verdict in enumerate(verdicts, start=1):
            step = AgentStep(
                task_id=task.id,
                position=start + offset,
                tool=verdict.step.tool[:64],
                target=verdict.step.target[:255],
                level=verdict.level,
                params=verdict.params if verdict.allowed else dict(verdict.step.params),
                reason=verdict.step.reason,
                source=source,
                status="planned" if verdict.allowed else "blocked",
                decision=verdict.code,
                decision_reason=verdict.reason,
            )
            self._session.add(step)
            self._session.flush()
            if not verdict.allowed:
                self._audit(
                    "system:plan-validator",
                    "agent_step_blocked",
                    verdict.reason,
                    task,
                    {
                        "step": str(step.id),
                        "source": source,
                        "tool": step.tool,
                        "target": step.target,
                        "code": verdict.code,
                        "plan_source": task.plan_source,
                    },
                )

    def _after_plan(
        self, task: AgentTask, plan: Plan, verdicts: Sequence[StepVerdict], actor: str
    ) -> None:
        allowed = sum(1 for v in verdicts if v.allowed)
        blocked = len(verdicts) - allowed
        self._audit(
            "system:plan-validator",
            "agent_plan_validated",
            f"Plan ({plan.source}): kroków do decyzji {allowed}, zablokowanych {blocked}",
            task,
            {"source": plan.source, "model": plan.model, "problems": plan.problems[:5]},
        )
        task.status = "awaiting_approval" if allowed else "done"
        if not allowed:
            task.finished_at = self._clock()
            task.summary = {
                **(task.summary or {}),
                "note": "Plan nie zawiera kroków, które można wykonać",
                "blocked": blocked,
            }

    # --- decyzje człowieka -----------------------------------------------------

    def approve(
        self,
        task_id: uuid.UUID,
        *,
        actor: str,
        reason: str,
        step_ids: Sequence[uuid.UUID] | None,
        can_approve_level: Callable[[int], bool],
    ) -> AgentTask:
        task = self._awaiting(task_id)
        if not reason.strip():
            raise AgentError("Zatwierdzenie wymaga powodu")
        if is_killed(self._session):
            raise AgentError("Agent jest wyłączony (kill switch)")
        planned = list(
            self._session.scalars(
                select(AgentStep)
                .where(AgentStep.task_id == task.id, AgentStep.status == "planned")
                .order_by(AgentStep.position)
            )
        )
        chosen = {s.id for s in planned} if step_ids is None else set(step_ids)
        unknown = chosen - {s.id for s in planned}
        if unknown:
            raise AgentError("Można zatwierdzić tylko kroki, które czekają na decyzję")
        for step in planned:
            if step.id in chosen and not can_approve_level(step.level):
                raise AgentError(f"Brak uprawnienia do zatwierdzenia kroku poziomu L{step.level}")
        if not chosen:
            raise AgentError("Nie wybrano żadnego kroku")
        for step in planned:
            step.status = "approved" if step.id in chosen else "skipped"
        task.status = "approved"
        task.approved_by = actor.split(":", 1)[-1]
        task.approval_reason = reason.strip()[:2000]
        task.approved_at = self._clock()
        self._audit(
            actor,
            "agent_task_approved",
            reason,
            task,
            {
                "approved_steps": [str(s.id) for s in planned if s.id in chosen],
                "skipped_steps": [str(s.id) for s in planned if s.id not in chosen],
                "levels": sorted({s.level for s in planned if s.id in chosen}),
            },
        )
        self._session.commit()
        return task

    def reject(self, task_id: uuid.UUID, *, actor: str, reason: str) -> AgentTask:
        task = self._awaiting(task_id)
        for step in self._session.scalars(
            select(AgentStep).where(AgentStep.task_id == task.id, AgentStep.status == "planned")
        ):
            step.status = "skipped"
        task.status = "rejected"
        task.finished_at = self._clock()
        self._audit(actor, "agent_task_rejected", reason or "Odrzucone", task, {})
        self._session.commit()
        return task

    def _awaiting(self, task_id: uuid.UUID) -> AgentTask:
        task = self._session.get(AgentTask, task_id)
        if task is None:
            raise AgentError("Nie znaleziono zadania")
        if task.status != "awaiting_approval":
            raise AgentError("To zadanie nie czeka na zatwierdzenie")
        return task

    # --- wykonanie -------------------------------------------------------------

    def execute(
        self,
        task_id: uuid.UUID,
        gateway: ToolGateway,
        *,
        after_tools: Callable[[Session], dict[str, Any]] | None = None,
    ) -> AgentTask:
        """Wykonuje zatwierdzone kroki po kolei. Przerywa po kill switchu."""
        session = self._session
        task = session.get(AgentTask, task_id)
        if task is None or task.status != "approved":
            raise AgentError("Zadanie nie jest zatwierdzone")
        task.status = "running"
        session.commit()
        steps = list(
            session.scalars(
                select(AgentStep)
                .where(AgentStep.task_id == task.id, AgentStep.status == "approved")
                .order_by(AgentStep.position)
            )
        )
        for step in steps:
            session.refresh(task)
            if task.status == "killed" or is_killed(session):
                break
            gateway.call(ToolRequest(step.id, step.tool, step.target, dict(step.params or {})))
            session.expire_all()
        session.refresh(task)
        if task.status == "killed":
            return task
        extra = after_tools(session) if after_tools else {}
        self._finish_round(task, extra)
        session.commit()
        return task

    def _finish_round(self, task: AgentTask, extra: dict[str, Any]) -> None:
        session = self._session
        all_steps = list(
            session.scalars(
                select(AgentStep).where(AgentStep.task_id == task.id).order_by(AgentStep.position)
            )
        )
        statuses = Counter(s.status for s in all_steps)
        task.summary = {
            **(task.summary or {}),
            "steps": dict(statuses),
            **extra,
        }
        rounds = int((task.summary or {}).get("follow_up_rounds", 0))
        capability = active_capability(session)
        if rounds < MAX_FOLLOW_UP_ROUNDS and capability is not None:
            results = [
                {"step": s.position, "tool": s.tool, "target": s.target, "result": s.result}
                for s in all_steps
                if s.status == "done"
            ]
            plan = self._planner.follow_up(
                task.command, capability, results, self._known_hosts(capability)
            )
            task.summary = {**task.summary, "follow_up_rounds": rounds + 1}
            if plan.steps:
                verdicts = self._validate(task, plan.steps, capability, source="follow_up")
                self._save_steps(task, verdicts, "follow_up")
                allowed = sum(1 for v in verdicts if v.allowed)
                self._audit(
                    "system:plan-validator",
                    "agent_follow_up_validated",
                    f"Kroki uzupełniające ({plan.source}): do decyzji {allowed}, "
                    f"zablokowanych {len(verdicts) - allowed}",
                    task,
                    {"source": plan.source, "model": plan.model},
                )
                if allowed:
                    task.status = "awaiting_approval"
                    return
        task.status = "done" if statuses.get("done") else "failed"
        task.finished_at = self._clock()
        self._audit(
            "system:agent-executor",
            "agent_task_finished",
            f"Zadanie zakończone: {dict(statuses)}",
            task,
            dict(task.summary or {}),
        )

    def _audit(
        self, actor: str, action: str, reason: str, task: AgentTask, inputs: dict[str, Any]
    ) -> None:
        audit.record(
            self._session,
            audit.AuditEvent(
                actor=actor,
                action=action,
                reason=reason,
                inputs={"task": str(task.id), "dry_run": task.dry_run, **inputs},
                object_type="agent_task",
                object_id=str(task.id),
                on_behalf_of=task.created_by if actor.startswith("system:") else None,
            ),
        )

    # --- zdolności i kill switch -----------------------------------------------

    def kill(self, *, actor: str, reason: str) -> dict[str, Any]:
        session = self._session
        switch = session.get(AgentSwitch, 1) or AgentSwitch(id=1)
        switch.killed = True
        switch.changed_by = actor
        switch.reason = reason[:2000]
        switch.changed_at = self._clock()
        session.add(switch)
        stopped = list(
            session.scalars(select(AgentTask.id).where(AgentTask.status.in_(ACTIVE_TASK_STATUSES)))
        )
        session.execute(
            update(AgentTask)
            .where(AgentTask.id.in_(stopped))
            .values(status="killed", finished_at=self._clock())
        )
        session.execute(
            update(AgentStep)
            .where(AgentStep.task_id.in_(stopped), AgentStep.status.in_(("planned", "approved")))
            .values(status="skipped", decision="agent_killed")
        )
        session.execute(update(AgentCapability).values(active=False))
        info = {"tasks_killed": [str(t) for t in stopped]}
        audit.record(
            session,
            audit.AuditEvent(
                actor=actor,
                action="agent_killed",
                reason=reason or "Kill switch",
                inputs=info,
                object_type="agent",
                object_id="sentinel-agent",
            ),
        )
        session.commit()
        return info


def create_capability(
    session: Session,
    *,
    actor: str,
    tools: Sequence[str],
    targets: Sequence[str],
    max_level: int,
    windows: Sequence[Any] = (),
    max_calls_per_task: int = 20,
    max_calls_per_target: int = 5,
    note: str = "",
    scope_check: Callable[[str], bool] | None = None,
) -> AgentCapability:
    """Nowa wersja zdolności (nieaktywna). Aktywuje ją dopiero zaliczony test (moduł 19)."""
    version = (session.scalar(select(func.max(AgentCapability.version))) or 0) + 1
    capability = Capability.build(
        version=version,
        tools=tools,
        targets=targets,
        max_level=max_level,
        windows=windows,
        max_calls_per_task=max_calls_per_task,
        max_calls_per_target=max_calls_per_target,
    )
    if scope_check is not None:
        outside = [t for t in capability.targets if not scope_check(t)]
        if outside:
            raise CapabilityError(f"Cele poza zakresem organizacji: {', '.join(outside)}")
    row = AgentCapability(
        version=version,
        tools=sorted(capability.tools),
        targets=list(capability.targets),
        max_level=capability.max_level,
        windows=list(windows),
        max_calls_per_task=capability.max_calls_per_task,
        max_calls_per_target=capability.max_calls_per_target,
        active=False,
        note=note[:2000],
        created_by=actor,
    )
    session.add(row)
    session.flush()
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="agent_capability_created",
            reason=note or "Nowa wersja zdolności agenta",
            inputs={
                "version": version,
                "tools": row.tools,
                "targets": row.targets,
                "max_level": row.max_level,
            },
            object_type="agent_capability",
            object_id=str(version),
        ),
    )
    return row


def activate_capability(session: Session, version: int, *, actor: str, reason: str) -> None:
    """Aktywuje wersję zdolności i zdejmuje kill switch (wywołuje bramka zmian)."""
    session.execute(update(AgentCapability).values(active=False))
    session.execute(
        update(AgentCapability).where(AgentCapability.version == version).values(active=True)
    )
    switch = session.get(AgentSwitch, 1)
    if switch is not None and switch.killed:
        switch.killed = False
        switch.changed_by = actor
        switch.reason = f"Nowa wersja zdolności {version}"
        switch.changed_at = utcnow()
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="agent_capability_activated",
            reason=reason,
            inputs={"version": version},
            object_type="agent_capability",
            object_id=str(version),
        ),
    )
