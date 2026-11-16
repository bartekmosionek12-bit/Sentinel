"""Wykonanie skanu: plan z reguł → scope_guard → narzędzie → inwentarz → analiza.

Każda akcja ma wiersz `ScanAction` z nazwą reguły i decyzją bramy. Akcje poziomu L2
bez zgody czekają w stanie `awaiting_approval` i nie uruchamiają żadnego narzędzia.
"""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.scope_guard import (
    ApprovalRequired,
    HumanApproval,
    Intrusiveness,
    ScopeError,
    ScopeGuard,
)
from app.feeds.base import as_utc
from app.inventory.service import record_discovery, record_host_scan
from app.matching.engine import ACTIVE_STATUSES
from app.models import Asset, Finding, ScanAction, ScanRun, Vulnerability
from app.models.base import utcnow
from app.notifications.channels import Sender
from app.pipeline import AnalysisReport, Rulebook, analyze
from app.planner.engine import FindingFact, HostFact, PlannedAction
from app.scanners.nmap import NmapAdapter
from app.scanners.runner import ToolError

FULL_PORTS = "1-65535"


class ScanActionError(Exception):
    """Akcji nie da się zatwierdzić ani odrzucić (brak albo zły stan)."""


def _hours_since(value: str | datetime | None, now: datetime) -> float | None:
    if value is None:
        return None
    try:
        moment = datetime.fromisoformat(value) if isinstance(value, str) else value
    except ValueError:
        return None
    return max(0.0, (now - as_utc(moment)).total_seconds() / 3600.0)


class ScanService:
    def __init__(
        self,
        session: Session,
        guard: ScopeGuard,
        rulebook: Rulebook,
        *,
        nmap: NmapAdapter | None = None,
        sender: Sender | None = None,
    ) -> None:
        self._session = session
        self._guard = guard
        self._rulebook = rulebook
        self._nmap = nmap or NmapAdapter()
        self._sender = sender

    @property
    def guard(self) -> ScopeGuard:
        return self._guard

    # --- pełny przebieg -------------------------------------------------

    def run(self, *, trigger: str, actor: str) -> ScanRun:
        session = self._session
        run = ScanRun(trigger=trigger, status="running")
        session.add(run)
        session.flush()
        self._audit(actor, "scan_started", f"Skan uruchomiony ({trigger})", {}, run)
        totals: Counter[str] = Counter()

        host_facts: list[HostFact] = []
        cidrs = [str(n) for n in self._guard.config.allowed_cidrs]
        for planned in self._rulebook.planner.sweep_actions(cidrs):
            host_facts += self._discover(run, planned, totals)

        for planned in self._rulebook.planner.host_actions(host_facts):
            self._scan_services(self._new_action(run, planned), totals)

        report = analyze(session, self._rulebook, self._sender)
        deep_scans = 0
        for planned in self._rulebook.planner.finding_actions(self._finding_facts()):
            deep_scans += self._scan_services(self._new_action(run, planned), totals)
        if deep_scans:
            second = analyze(session, self._rulebook, self._sender)
            report = _merge(report, second)

        statuses = Counter(
            session.scalars(select(ScanAction.status).where(ScanAction.scan_run_id == run.id))
        )
        run.summary = {
            **totals,
            **report.summary(),
            "actions": dict(statuses),
            "note": "" if cidrs else "Zakres jest pusty, więc nic nie zostało zeskanowane",
        }
        run.status = "done"
        run.finished_at = utcnow()
        self._audit(actor, "scan_finished", "Skan zakończony", run.summary, run)
        session.commit()
        return run

    # --- decyzje człowieka ----------------------------------------------

    def approve(self, action_id: uuid.UUID, *, approved_by: str, reason: str) -> ScanAction:
        action = self._awaiting(action_id)
        self._audit(
            f"user:{approved_by}",
            "scan_action_approved",
            reason,
            {"target": action.target, "rule": action.rule_name, "tool": action.tool},
            action,
        )
        ran = self._scan_services(
            action, Counter(), HumanApproval(approved_by=approved_by, reason=reason)
        )
        if ran:
            analyze(self._session, self._rulebook, self._sender)
        self._session.commit()
        return action

    def reject(self, action_id: uuid.UUID, *, rejected_by: str, reason: str) -> ScanAction:
        action = self._awaiting(action_id)
        action.status = "denied"
        action.scope_decision = "rejected_by_human"
        action.detail = reason
        action.finished_at = utcnow()
        self._audit(
            f"user:{rejected_by}",
            "scan_action_rejected",
            reason,
            {"target": action.target, "rule": action.rule_name, "tool": action.tool},
            action,
        )
        self._session.commit()
        return action

    def _awaiting(self, action_id: uuid.UUID) -> ScanAction:
        action = self._session.get(ScanAction, action_id)
        if action is None:
            raise ScanActionError("Nie znaleziono akcji")
        if action.status != "awaiting_approval":
            raise ScanActionError("Ta akcja nie czeka na zatwierdzenie")
        return action

    # --- kroki ----------------------------------------------------------

    def _audit(
        self,
        actor: str,
        action: str,
        reason: str,
        inputs: dict[str, Any],
        obj: ScanRun | ScanAction,
    ) -> None:
        audit.record(
            self._session,
            audit.AuditEvent(
                actor=actor,
                action=action,
                reason=reason,
                inputs=inputs,
                object_type="scan_run" if isinstance(obj, ScanRun) else "scan_action",
                object_id=str(obj.id),
            ),
        )

    def _new_action(self, run: ScanRun, planned: PlannedAction) -> ScanAction:
        action = ScanAction(
            scan_run_id=run.id,
            asset_id=planned.asset_id,
            target=planned.target,
            tool=planned.tool,
            rule_name=planned.rule,
            intrusiveness=int(planned.intrusiveness),
            params={"mode": planned.mode, "ports": planned.ports},
            reason=planned.reason,
        )
        self._session.add(action)
        self._session.flush()
        return action

    def _finish(self, action: ScanAction, status: str, detail: str) -> None:
        action.status = status
        action.detail = detail
        action.finished_at = utcnow()
        self._audit(
            f"rule:{action.rule_name}",
            f"scan_action_{status}",
            detail,
            {
                "target": action.target,
                "tool": action.tool,
                "intrusiveness": action.intrusiveness,
                "params": action.params,
                "scope_decision": action.scope_decision,
                "approval_source": action.approval_source,
                "planned_because": action.reason,
            },
            action,
        )

    def _discover(
        self, run: ScanRun, planned: PlannedAction, totals: Counter[str]
    ) -> list[HostFact]:
        session = self._session
        action = self._new_action(run, planned)
        # Brama zapisuje decyzję w osobnej transakcji, więc najpierw zamykamy własną.
        session.commit()
        try:
            network = self._guard.authorize_network(
                planned.target,
                tool=planned.tool,
                intrusiveness=planned.intrusiveness,
                rule_name=planned.rule,
            )
        except ScopeError as error:
            action.scope_decision = error.code
            self._finish(action, "denied", error.reason)
            return []
        action.scope_decision = "scope_allowed"
        action.status = "running"
        session.commit()
        try:
            hosts = self._nmap.discover(network)
        except ToolError as error:
            self._finish(action, "failed", str(error))
            return []
        result = record_discovery(session, network, hosts, run.id)
        totals["hosts_up"] += len(result.seen)
        totals["hosts_new"] += len(result.new)
        totals["hosts_reappeared"] += len(result.reappeared)
        totals["hosts_missing"] += len(result.missing)
        self._finish(
            action,
            "done",
            f"Odpowiada hostów: {len(result.seen)}, nowych: {len(result.new)}, "
            f"wróciło: {len(result.reappeared)}, nie odpowiada: {len(result.missing)}",
        )
        now = utcnow()
        new = {a.id for a in result.new}
        back = {a.id for a in result.reappeared}
        return [
            HostFact(
                asset_id=asset.id,
                address=str(asset.attributes["address"]),
                state="new" if asset.id in new else "reappeared" if asset.id in back else "known",
                hours_since_service_scan=_hours_since(
                    asset.attributes.get("last_service_scan"), now
                ),
            )
            for asset in result.seen
        ]

    def _scan_services(
        self,
        action: ScanAction,
        totals: Counter[str],
        approval: HumanApproval | None = None,
    ) -> int:
        """Zwraca 1, gdy narzędzie faktycznie się wykonało."""
        session = self._session
        session.commit()
        try:
            target = self._guard.authorize(
                action.target,
                tool=action.tool,
                intrusiveness=Intrusiveness(action.intrusiveness),
                rule_name=action.rule_name,
                approval=approval,
            )
        except ApprovalRequired as error:
            action.status = "awaiting_approval"
            action.scope_decision = error.code
            action.detail = error.reason
            totals["awaiting_approval"] += 1
            return 0
        except ScopeError as error:
            action.scope_decision = error.code
            self._finish(action, "denied", error.reason)
            return 0
        action.scope_decision = "scope_allowed"
        action.approval_source = target.approval_source
        action.status = "running"
        session.commit()
        ports = str(action.params.get("ports") or "top-1000")
        full = ports == FULL_PORTS
        try:
            scan = self._nmap.scan_services(target, ports=ports, timeout=1200 if full else 300)
        except ToolError as error:
            self._finish(action, "failed", str(error))
            return 0
        asset = session.get(Asset, action.asset_id) if action.asset_id else None
        if asset is None:
            self._finish(action, "failed", "Zasób został usunięty przed zapisaniem wyniku")
            return 0
        diff = record_host_scan(session, asset, scan, action.scan_run_id, full=full)
        totals["services_added"] += len(diff.added)
        totals["services_removed"] += len(diff.removed)
        self._finish(
            action,
            "done",
            f"Otwartych portów: {len(scan.services)}, nowych usług: {len(diff.added)}, "
            f"zniknęło: {len(diff.removed)}",
        )
        return 1

    def _finding_facts(self) -> list[FindingFact]:
        session = self._session
        now = utcnow()
        kev_by_asset: dict[uuid.UUID, bool] = {}
        for asset_id, in_kev in session.execute(
            select(Finding.asset_id, func.max(func.coalesce(Vulnerability.in_kev, False)))
            .outerjoin(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
            .where(Finding.status.in_(ACTIVE_STATUSES))
            .group_by(Finding.asset_id)
        ):
            kev_by_asset[asset_id] = bool(in_kev)
        facts: list[FindingFact] = []
        for asset_id, in_kev in kev_by_asset.items():
            asset = session.get(Asset, asset_id)
            address = (asset.attributes or {}).get("address") if asset else None
            if asset is None or asset.type != "host" or not address or asset.status == "missing":
                continue
            last: dict[str, float] = {}
            pending: set[str] = set()
            for rule, status, finished in session.execute(
                select(ScanAction.rule_name, ScanAction.status, ScanAction.finished_at).where(
                    ScanAction.asset_id == asset_id,
                    ScanAction.status.in_(("done", "awaiting_approval")),
                )
            ):
                if status == "awaiting_approval":
                    pending.add(rule)
                    continue
                hours = _hours_since(finished, now)
                if hours is not None:
                    last[rule] = min(hours, last.get(rule, hours))
            facts.append(FindingFact(asset_id, str(address), in_kev, last, frozenset(pending)))
        return facts


def _merge(first: AnalysisReport, second: AnalysisReport) -> AnalysisReport:
    first.products.auto += second.products.auto
    first.products.needs_review += second.products.needs_review
    first.products.unmatched += second.products.unmatched
    first.findings.changes += second.findings.changes
    first.findings.undetermined = second.findings.undetermined
    first.notifications += second.notifications
    return first
