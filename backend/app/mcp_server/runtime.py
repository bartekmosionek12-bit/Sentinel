"""Wykonanie narzędzia MCP dla kroku agenta: jedyna ścieżka od planu do sieci.

Kolejność (ARCHITECTURE §5.1, §3): krok z bazy (nie z wywołania) → zgodność wywołania z
krokiem → zatwierdzenie przez człowieka → kill switch → polityka zdolności → `scope_guard`
→ poświadczenie JIT (tylko gdy narzędzie go wymaga) → adapter → odwołanie poświadczenia →
zapis w inwentarzu → audyt → przefiltrowany wynik.

Serwer nie ufa temu, co przysyła wywołujący: narzędzie, cel i parametry muszą zgadzać się z
krokiem zatwierdzonym przez człowieka. Poziom pochodzi z katalogu narzędzi.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.agent import policy
from app.agent.capability import Capability
from app.agent.catalog import ToolSpec
from app.agent.switch import is_killed
from app.core import audit
from app.core.scope_guard import (
    HumanApproval,
    Intrusiveness,
    ScopedNetwork,
    ScopedTarget,
    ScopeError,
    ScopeGuard,
)
from app.credentials.openbao import SSH_TTL, SignedCertificate, Vault, VaultError
from app.inventory.service import (
    host_asset,
    record_discovery,
    record_host_scan,
    record_packages,
)
from app.mcp_server.filtering import for_agent, scrub
from app.models import AgentCapability, AgentStep, AgentTask, CredentialLease
from app.models.base import utcnow
from app.scanners.http_probe import HttpProber
from app.scanners.nmap import NmapAdapter
from app.scanners.nuclei import NucleiAdapter
from app.scanners.runner import ToolError
from app.scanners.ssh import SshConnector, check_level, collect_packages, new_keypair

FULL_PORTS = "1-65535"
RULE_PREFIX = "agent"


@dataclass(frozen=True)
class ToolRequest:
    step_id: uuid.UUID
    tool: str
    target: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolResponse:
    allowed: bool
    code: str
    reason: str
    result: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "code": self.code,
            "reason": self.reason,
            "result": self.result,
        }


@dataclass
class Toolbox:
    nmap: NmapAdapter
    http: HttpProber
    nuclei: NucleiAdapter | None = None
    ssh: SshConnector | None = None
    vault: Vault | None = None
    ssh_username: str = "sentinel-scan"


class _Denied(Exception):
    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


def active_capability(session: Session) -> Capability | None:
    row = session.scalar(
        select(AgentCapability)
        .where(AgentCapability.active.is_(True))
        .order_by(AgentCapability.version.desc())
    )
    return Capability.from_model(row) if row else None


class ToolRuntime:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        guard: ScopeGuard,
        toolbox: Toolbox,
        *,
        caller: str = "agent:sentinel-agent",
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._sessions = sessions
        self._guard = guard
        self._tools = toolbox
        self._caller = caller
        self._clock = clock

    # --- wejście ----------------------------------------------------------

    def call(self, request: ToolRequest) -> ToolResponse:
        with self._sessions() as session:
            step = session.get(AgentStep, request.step_id)
            task = session.get(AgentTask, step.task_id) if step else None
            if step is None or task is None:
                self._audit(
                    session, None, "mcp_call_denied", "Nieznany krok zadania", request, None
                )
                session.commit()
                return ToolResponse(False, "unknown_step", "Nie ma takiego kroku zadania")
            try:
                spec = self._preflight(session, task, step, request)
                scoped = self._authorize(session, task, step, spec)
            except _Denied as denied:
                return self._deny(session, task, step, request, denied)
            step.status = "running"
            step.started_at = self._clock()
            step.decision = policy.ALLOWED
            step.decision_reason = "Polityka i scope_guard zezwoliły"
            session.commit()
            try:
                raw = self._execute(session, task, step, spec, scoped)
            except (ToolError, VaultError) as error:
                session.rollback()
                step = session.get(AgentStep, request.step_id) or step
                step.status = "failed"
                step.finished_at = self._clock()
                step.result = {"error": scrub(str(error), 300)}
                self._audit(
                    session, task, "agent_tool_failed", scrub(str(error), 300), request, step
                )
                session.commit()
                return ToolResponse(False, "tool_error", scrub(str(error), 300))
            filtered = for_agent(raw)
            step.status = "done"
            step.finished_at = self._clock()
            step.result = filtered
            self._audit(
                session,
                task,
                "agent_tool_called",
                f"Narzędzie {spec.name} wykonane na {step.target}",
                request,
                step,
                {"result_keys": sorted(filtered)},
            )
            session.commit()
            return ToolResponse(True, policy.ALLOWED, "Wykonano", filtered)

    # --- decyzje ------------------------------------------------------------

    def _preflight(
        self, session: Session, task: AgentTask, step: AgentStep, request: ToolRequest
    ) -> ToolSpec:
        if (request.tool, request.target.strip(), dict(request.params or {})) != (
            step.tool,
            step.target,
            dict(step.params or {}),
        ):
            raise _Denied(
                "step_mismatch",
                "Wywołanie nie zgadza się z zatwierdzonym krokiem (narzędzie, cel albo parametry)",
            )
        if task.dry_run:
            raise _Denied(
                "dry_run_task", "Zadanie w trybie dry-run nie dostaje prawdziwych narzędzi"
            )
        if task.status != "running" or not task.approved_by:
            raise _Denied("not_approved", "Zadanie nie zostało zatwierdzone przez człowieka")
        if step.status != "approved":
            raise _Denied("step_not_approved", f"Krok ma status {step.status}, nie approved")
        started = (
            select(func.count())
            .select_from(AgentStep)
            .where(AgentStep.task_id == task.id, AgentStep.started_at.is_not(None))
        )
        calls_in_task = session.scalar(started) or 0
        calls_for_target = session.scalar(started.where(AgentStep.target == step.target)) or 0
        decision = policy.check_call(
            active_capability(session),
            step.tool,
            step.target,
            killed=is_killed(session),
            now=self._clock(),
            calls_in_task=calls_in_task,
            calls_for_target=calls_for_target,
        )
        if not decision.allowed or decision.spec is None:
            raise _Denied(decision.code, decision.reason)
        return decision.spec

    def _authorize(
        self, session: Session, task: AgentTask, step: AgentStep, spec: ToolSpec
    ) -> ScopedTarget | ScopedNetwork:
        # scope_guard zapisuje decyzję w osobnej transakcji: najpierw zamykamy własną.
        session.commit()
        rule = f"{RULE_PREFIX}:{task.id}:{step.position}"
        try:
            if spec.target_kind == "network":
                return self._guard.authorize_network(
                    step.target, tool=spec.name, intrusiveness=spec.level, rule_name=rule
                )
            approval = None
            if spec.level >= Intrusiveness.INTRUSIVE:
                approval = HumanApproval(
                    approved_by=task.approved_by or "", reason=task.approval_reason or ""
                )
            return self._guard.authorize(
                step.target,
                tool=spec.name,
                intrusiveness=spec.level,
                rule_name=rule,
                approval=approval,
            )
        except ScopeError as error:
            raise _Denied(error.code, error.reason) from error

    def _deny(
        self,
        session: Session,
        task: AgentTask,
        step: AgentStep,
        request: ToolRequest,
        denied: _Denied,
    ) -> ToolResponse:
        # Krok, którego nikt nie zatwierdził, zostaje w swoim stanie; zatwierdzony blokujemy.
        if step.status in ("approved", "running"):
            step.status = "blocked"
            step.finished_at = self._clock()
        step.decision = denied.code
        step.decision_reason = denied.reason
        self._audit(
            session, task, "mcp_call_denied", denied.reason, request, step, {"code": denied.code}
        )
        session.commit()
        return ToolResponse(False, denied.code, denied.reason)

    # --- wykonanie ----------------------------------------------------------

    def _execute(
        self,
        session: Session,
        task: AgentTask,
        step: AgentStep,
        spec: ToolSpec,
        scoped: ScopedTarget | ScopedNetwork,
    ) -> dict[str, Any]:
        params = dict(step.params or {})
        if isinstance(scoped, ScopedNetwork):
            hosts = self._tools.nmap.discover(scoped)
            found = record_discovery(session, scoped, hosts)
            return {
                "network": str(scoped.network),
                "hosts_up": [str(a.attributes.get("address")) for a in found.seen],
                "new_hosts": [str(a.attributes.get("address")) for a in found.new],
                "missing_hosts": [str(a.attributes.get("address")) for a in found.missing],
            }
        asset = host_asset(session, scoped.address, scoped.hostname)
        if spec.name in ("scan_services", "scan_all_ports"):
            full = spec.name == "scan_all_ports"
            ports = FULL_PORTS if full else str(params.get("ports") or "top-1000")
            scan = self._tools.nmap.scan_services(
                scoped, ports=ports, timeout=1200 if full else 300
            )
            diff = record_host_scan(session, asset, scan, full=full)
            return {
                "host": scoped.address,
                "open_ports": sorted(s.port for s in scan.services),
                "new_services": len(diff.added),
                "removed_services": len(diff.removed),
                "untrusted": {
                    "services": [
                        {
                            "port": s.port,
                            "protocol": s.protocol,
                            "name": s.name,
                            "product": s.product,
                            "version": s.version,
                            "banner": s.banner,
                        }
                        for s in scan.services
                    ]
                },
            }
        if spec.name == "probe_http":
            port = int(params.get("port") or 80)
            scheme = str(params.get("scheme") or "http")
            page = self._tools.http.probe(scoped, port=port, scheme=scheme)
            attributes = dict(asset.attributes or {})
            web = dict(attributes.get("http") or {})
            web[str(port)] = {"status": page.status, "server": page.server, "title": page.title}
            asset.attributes = {**attributes, "http": web}
            session.flush()
            return {
                "host": scoped.address,
                "port": port,
                "status": page.status,
                "untrusted": {"server": page.server, "title": page.title},
            }
        if spec.name == "verify_cve":
            if self._tools.nuclei is None:
                raise ToolError("nuclei nie jest skonfigurowany")
            cve_id = str(params.get("cve_id") or "")
            port = int(params.get("port") or 80)
            matches = self._tools.nuclei.verify(scoped, cve_id=cve_id, port=port)
            attributes = dict(asset.attributes or {})
            verified = dict(attributes.get("verified_cves") or {})
            verified[cve_id.upper()] = {
                "confirmed": bool(matches),
                "templates": [m.template_id for m in matches],
                "checked_at": self._clock().isoformat(),
            }
            asset.attributes = {**attributes, "verified_cves": verified}
            session.flush()
            return {
                "host": scoped.address,
                "cve_id": cve_id.upper(),
                "confirmed": bool(matches),
                "templates": [m.template_id for m in matches],
            }
        if spec.name == "collect_software_authenticated":
            return self._authenticated(session, task, step, scoped, asset)
        raise ToolError(f"Brak implementacji narzędzia {spec.name}")

    def _authenticated(
        self, session: Session, task: AgentTask, step: AgentStep, scoped: ScopedTarget, asset: Any
    ) -> dict[str, Any]:
        check_level(scoped)
        if self._tools.vault is None or self._tools.ssh is None:
            raise ToolError("Skan uwierzytelniony wymaga OpenBao i klienta SSH")
        private_key, public_key = new_keypair()
        cert: SignedCertificate = self._tools.vault.sign_ssh_key(
            public_key, principal=self._tools.ssh_username
        )
        lease = CredentialLease(
            task_id=task.id,
            step_id=step.id,
            kind="ssh_cert",
            target=scoped.address,
            principal=cert.principal,
            serial=cert.serial,
            lease_id=cert.token_accessor,
            ttl_seconds=int(SSH_TTL.total_seconds()),
            issued_by="mcp-scanner",
            expires_at=cert.expires_at,
        )
        session.add(lease)
        session.flush()
        self._audit_simple(
            session,
            task,
            "credential_issued",
            f"Certyfikat SSH na 15 minut dla {scoped.address}",
            {"serial": cert.serial, "principal": cert.principal, "lease": str(lease.id)},
        )
        session.commit()
        try:
            connection = self._tools.ssh.connect(
                scoped,
                username=cert.principal,
                private_key=private_key,
                certificate=cert.certificate,
            )
            try:
                manager, packages = collect_packages(connection)
            finally:
                connection.close()
        finally:
            del private_key
            try:
                self._tools.vault.revoke(cert)
            finally:
                lease.revoked_at = self._clock()
                lease.revoked_by = "mcp-scanner"
                self._audit_simple(
                    session,
                    task,
                    "credential_revoked",
                    "Token OpenBao odwołany po zadaniu; certyfikat wygasa po TTL",
                    {"serial": cert.serial, "lease": str(lease.id)},
                )
                session.commit()
        diff = record_packages(session, asset, manager, [(p.name, p.version) for p in packages])
        return {
            "host": scoped.address,
            "package_manager": manager,
            "packages": len(packages),
            "new_packages": len(diff.added),
            "removed_packages": len(diff.removed),
        }

    # --- audyt --------------------------------------------------------------

    def _audit(
        self,
        session: Session,
        task: AgentTask | None,
        action: str,
        reason: str,
        request: ToolRequest,
        step: AgentStep | None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        audit.record(
            session,
            audit.AuditEvent(
                actor=self._caller,
                action=action,
                reason=reason,
                inputs={
                    "task": str(task.id) if task else None,
                    "step": str(request.step_id),
                    "tool": request.tool,
                    "target": request.target[:255],
                    "params": {k: str(v)[:100] for k, v in (request.params or {}).items()},
                    **(extra or {}),
                },
                object_type="agent_step",
                object_id=str(step.id) if step else str(request.step_id),
                actor_type="agent",
                on_behalf_of=task.approved_by if task else None,
            ),
        )

    def _audit_simple(
        self, session: Session, task: AgentTask, action: str, reason: str, inputs: dict[str, Any]
    ) -> None:
        audit.record(
            session,
            audit.AuditEvent(
                actor="system:mcp-scanner",
                action=action,
                reason=reason,
                inputs={"task": str(task.id), **inputs},
                object_type="credential_lease",
                object_id=str(inputs.get("lease")),
                actor_type="system",
                on_behalf_of=task.approved_by,
            ),
        )
