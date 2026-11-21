"""Wykonanie skanu: plan z reguł → scope_guard → narzędzie → inwentarz → analiza.

Każda akcja ma wiersz `ScanAction` z nazwą reguły i decyzją bramy. Akcje poziomu L2
bez zgody czekają w stanie `awaiting_approval` i nie uruchamiają żadnego narzędzia.
"""

from __future__ import annotations

import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from ipaddress import ip_network
from typing import Any

from sqlalchemy import select
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
        started = time.monotonic()
        run = ScanRun(trigger=trigger, status="running")
        session.add(run)
        session.flush()
        self._audit(actor, "scan_started", f"Skan uruchomiony ({trigger})", {}, run)
        totals: Counter[str] = Counter()

        host_facts: list[HostFact] = []
        cidrs = [str(n) for n in self._guard.config.allowed_cidrs]
        run.summary = {
            "total_addresses": sum(n.num_addresses for n in self._guard.config.allowed_cidrs),
            "addresses_done": 0,
            "eta_seconds": None,
        }
        session.commit()
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
            **run.summary,
            **totals,
            **report.summary(),
            "actions": dict(statuses),
            "note": "" if cidrs else "Zakres jest pusty, więc nic nie zostało zeskanowane",
        }
        run.status = "done"
        run.finished_at = utcnow()
        run.summary = {
            **run.summary,
            "duration_seconds": round(time.monotonic() - started, 2),
            "eta_seconds": 0,
        }
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
        """Autoryzuj każdą paczkę, skanuj równolegle i zapisuj wynik po każdej paczce."""
        session = self._session
        base = ip_network(planned.target)
        workers = self._guard.config.scan_workers
        rate = max(1, self._guard.config.scan_packets_per_second // workers)
        batch_size = base.num_addresses if base.num_addresses <= 1024 else 64
        offset = 0
        facts: list[HostFact] = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            while offset < base.num_addresses:
                jobs = {}
                for _ in range(workers):
                    if offset >= base.num_addresses:
                        break
                    size = min(batch_size, base.num_addresses - offset)
                    # Paczki są potęgami dwójki, wyrównanymi w obrębie CIDR.
                    while size > 1 and offset % size:
                        size //= 2
                    chunk = ip_network(
                        (
                            int(base.network_address) + offset,
                            base.max_prefixlen - (size.bit_length() - 1),
                        )
                    )
                    offset += size
                    chunk_plan = PlannedAction(
                        target=str(chunk),
                        tool=planned.tool,
                        mode=planned.mode,
                        ports=planned.ports,
                        intrusiveness=planned.intrusiveness,
                        rule=planned.rule,
                        reason=planned.reason,
                        asset_id=planned.asset_id,
                    )
                    action = self._new_action(run, chunk_plan)
                    session.commit()
                    try:
                        network = self._guard.authorize_network(
                            str(chunk),
                            tool=planned.tool,
                            intrusiveness=planned.intrusiveness,
                            rule_name=planned.rule,
                        )
                    except ScopeError as error:
                        action.scope_decision = error.code
                        self._finish(action, "denied", error.reason)
                        session.commit()
                        continue
                    action.scope_decision = "scope_allowed"
                    action.status = "running"
                    session.commit()
                    jobs[pool.submit(self._nmap.discover, network, packets_per_second=rate)] = (
                        action,
                        network,
                        time.monotonic(),
                    )
                durations = []
                for future in as_completed(jobs):
                    action, network, began = jobs[future]
                    duration = round(time.monotonic() - began, 2)
                    durations.append(duration)
                    try:
                        hosts = future.result()
                    except Exception as error:
                        self._finish(action, "failed", str(error))
                    else:
                        result = record_discovery(session, network, hosts, run.id)
                        totals["hosts_up"] += len(result.seen)
                        totals["hosts_new"] += len(result.new)
                        totals["hosts_reappeared"] += len(result.reappeared)
                        totals["hosts_missing"] += len(result.missing)
                        self._finish(
                            action,
                            "done",
                            f"{duration}s; aktywne: {len(result.seen)}, nowe: {len(result.new)}, "
                            f"brak: {len(result.missing)}",
                        )
                        now = utcnow()
                        new = {a.id for a in result.new}
                        back = {a.id for a in result.reappeared}
                        facts.extend(
                            HostFact(
                                asset_id=asset.id,
                                address=str(asset.attributes["address"]),
                                state="new"
                                if asset.id in new
                                else "reappeared"
                                if asset.id in back
                                else "known",
                                hours_since_service_scan=_hours_since(
                                    asset.attributes.get("last_service_scan"), now
                                ),
                            )
                            for asset in result.seen
                        )
                    done = int(run.summary.get("addresses_done", 0)) + network.network.num_addresses
                    total = int(run.summary["total_addresses"])
                    elapsed = (utcnow() - run.started_at).total_seconds()
                    run.summary = {
                        **run.summary,
                        **totals,
                        "addresses_done": done,
                        "eta_seconds": round(elapsed * (total - done) / done) if done else None,
                        "last_batch_seconds": duration,
                    }
                    session.commit()
                if (
                    durations
                    and max(durations) < 20
                    and batch_size < 256
                    and offset % (batch_size * 2) == 0
                ):
                    batch_size *= 2
                elif durations and max(durations) > 90 and batch_size > 32:
                    batch_size //= 2
        return facts

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
        began = time.monotonic()
        try:
            scan = self._nmap.scan_services(
                target,
                ports=ports,
                timeout=1200 if full else 300,
                packets_per_second=self._guard.config.scan_packets_per_second,
            )
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
            f"{time.monotonic() - began:.2f}s; otwartych portów: {len(scan.services)}, "
            f"nowych usług: {len(diff.added)}, "
            f"zniknęło: {len(diff.removed)}",
        )
        return 1

    def _finding_facts(self) -> list[FindingFact]:
        session = self._session
        now = utcnow()
        kev_by_asset: dict[uuid.UUID, bool] = {}
        for asset_id, in_kev in session.execute(
            select(Finding.asset_id, Vulnerability.in_kev)
            .outerjoin(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
            .where(Finding.status.in_(ACTIVE_STATUSES))
        ):
            kev_by_asset[asset_id] = kev_by_asset.get(asset_id, False) or bool(in_kev)
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
