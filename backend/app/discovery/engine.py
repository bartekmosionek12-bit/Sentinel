"""Silnik discovery: cele (IP, CIDR, domeny) → paczki o adaptacyjnym rozmiarze → równoległe
workery nmap -sn → aktywne hosty → nmap -sV i fingerprinting HTTP → zapis po każdej paczce.

Bezpieczeństwo:
* każda paczka i każdy host przechodzi przez `scope_guard` (wątek główny; workery dostają
  tylko gotowe `ScopedNetwork`/`ScopedTarget`),
* nmap nigdy agresywniej niż -T3, z limitem `--max-rate` (pakiety/s) na proces,
* liczba równoległych procesów ograniczona `workers`, wszystko z górnymi limitami z pliku.

Pomiar: czas każdej paczki i całego przebiegu, ETA z mierzonej szybkości, zapis przyrostowy.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
import uuid
from collections import deque
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.scope_guard import (
    Intrusiveness,
    ScopedNetwork,
    ScopedTarget,
    ScopeError,
    ScopeGuard,
)
from app.discovery.fingerprint import HttpFingerprinter, flags_for, web_ports
from app.models import DiscoveryBatch, DiscoveryRun, Observation
from app.models.base import utcnow
from app.scanners.models import DiscoveredHost, HostScan
from app.scanners.nmap import NmapAdapter
from app.scanners.runner import ToolError

logger = logging.getLogger("sentinel.discovery")
IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class DiscoverySettings:
    workers: int = 4
    max_rate: int = 300
    timing: int = 3
    batch_initial: int = 256
    batch_min: int = 16
    batch_max: int = 4096
    batch_target_seconds: float = 20.0
    discovery_ports: str = "22,80,443,8080"
    service_ports: str = "22,80,443,8080"
    http_paths: tuple[str, ...] = ("/admin", "/login")
    fingerprint: bool = True


@dataclass(frozen=True)
class DiscoveryConfig:
    defaults: DiscoverySettings
    limits: dict[str, int]
    inactive_after_runs: int = 3
    window: int = 5

    @classmethod
    def from_file(cls, path: Path) -> DiscoveryConfig:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
        raw = dict(data.get("defaults") or {})
        if "http_paths" in raw:
            raw["http_paths"] = tuple(raw["http_paths"])
        state = data.get("host_state") or {}
        return cls(
            defaults=DiscoverySettings(**raw),
            limits={k: int(v) for k, v in (data.get("limits") or {}).items()},
            inactive_after_runs=int(state.get("inactive_after_runs", 3)),
            window=int(state.get("window", 5)),
        )

    def settings(self, overrides: dict[str, Any] | None = None) -> DiscoverySettings:
        """Ustawienia przebiegu: domyślne + zmiany z UI, zawsze przycięte do limitów."""
        values = asdict(self.defaults)
        for key, value in (overrides or {}).items():
            if key in values and value not in (None, ""):
                values[key] = value
        values["http_paths"] = tuple(values["http_paths"])
        workers = max(1, min(int(values["workers"]), self.limits.get("workers", 16)))
        rate = max(10, min(int(values["max_rate"]), self.limits.get("max_rate", 2000)))
        timing = max(0, min(int(values["timing"]), self.limits.get("timing", 3), 3))
        return replace(
            DiscoverySettings(**values),
            workers=workers,
            max_rate=rate,
            timing=timing,
            batch_min=max(1, int(values["batch_min"])),
            batch_max=min(4096, int(values["batch_max"])),
        )


@dataclass
class ParsedTargets:
    networks: list[IpNetwork] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def addresses(self) -> int:
        return sum(n.num_addresses for n in self.networks) + len(self.domains)


_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def parse_targets(items: list[str]) -> ParsedTargets:
    """IP, CIDR (także zapisany niestrykt, np. 10.0.0.5/24) i domeny; reszta jako błąd."""
    out = ParsedTargets()
    seen: set[str] = set()
    for raw in items:
        value = raw.strip().lower()
        if not value or value.startswith("#") or value in seen:
            continue
        seen.add(value)
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            if _DOMAIN.match(value):
                out.domains.append(value)
            else:
                out.errors.append(f"{raw.strip()[:80]}: to nie jest IP, CIDR ani domena")
            continue
        if network.version == 6 and network.num_addresses > 1:
            out.errors.append(f"{value}: zakresy IPv6 nie są obsługiwane (tylko pojedyncze adresy)")
            continue
        out.networks.append(network)
    v4 = [n for n in out.networks if isinstance(n, ipaddress.IPv4Network)]
    v6 = [n for n in out.networks if isinstance(n, ipaddress.IPv6Network)]
    out.networks = [*ipaddress.collapse_addresses(v4), *ipaddress.collapse_addresses(v6)]
    return out


def _power_of_two(value: float, low: int, high: int) -> int:
    size = low
    while size * 2 <= min(value, high):
        size *= 2
    return max(low, min(size, high))


class BatchQueue:
    """Kolejka sieci do przeskanowania; kolejna paczka ma zadany rozmiar (potęga dwójki)."""

    def __init__(self, networks: list[IpNetwork]) -> None:
        self._queue: deque[IpNetwork] = deque(networks)

    def __bool__(self) -> bool:
        return bool(self._queue)

    def take(self, size: int) -> IpNetwork:
        network = self._queue.popleft()
        if network.num_addresses <= size:
            return network
        prefix = network.max_prefixlen - (size.bit_length() - 1)
        parts: list[IpNetwork] = list(network.subnets(new_prefix=prefix))
        self._queue.extendleft(reversed(parts[1:]))
        return parts[0]


@dataclass
class SweepResult:
    network: ScopedNetwork
    hosts: list[DiscoveredHost]
    seconds: float
    error: str | None = None


@dataclass
class ServiceResult:
    ip: str
    scan: HostScan | None
    http: list[dict[str, Any]]
    seconds: float
    error: str | None = None


def service_dicts(scan: HostScan) -> list[dict[str, Any]]:
    return [
        {
            "port": s.port,
            "protocol": s.protocol,
            "name": s.name,
            "product": s.product,
            "version": s.version,
            "extrainfo": s.extrainfo,
        }
        for s in scan.services
    ]


class DiscoveryEngine:
    def __init__(
        self,
        session: Session,
        guard: ScopeGuard,
        config: DiscoveryConfig,
        *,
        nmap: NmapAdapter | None = None,
        fingerprinter: HttpFingerprinter | None = None,
    ) -> None:
        self._session = session
        self._guard = guard
        self._config = config
        self._nmap = nmap or NmapAdapter()
        self._fingerprinter = fingerprinter

    # --- kroki wykonywane w workerach (bez bazy i bez bramy) -------------------------

    def _sweep(self, network: ScopedNetwork, settings: DiscoverySettings) -> SweepResult:
        started = time.monotonic()
        try:
            hosts = self._nmap.discover_batch(
                network,
                ports=settings.discovery_ports,
                timing=settings.timing,
                max_rate=settings.max_rate,
            )
        except ToolError as error:
            return SweepResult(network, [], time.monotonic() - started, str(error))
        return SweepResult(network, hosts, time.monotonic() - started)

    def _services(
        self,
        target: ScopedTarget,
        http_target: ScopedTarget | None,
        settings: DiscoverySettings,
    ) -> ServiceResult:
        started = time.monotonic()
        try:
            scan = self._nmap.scan_services(
                target,
                ports=settings.service_ports,
                timing=settings.timing,
                max_rate=settings.max_rate,
            )
        except ToolError as error:
            return ServiceResult(target.address, None, [], time.monotonic() - started, str(error))
        http: list[dict[str, Any]] = []
        if http_target is not None and settings.fingerprint:
            prober = self._fingerprinter or HttpFingerprinter(list(settings.http_paths))
            try:
                for port, scheme in web_ports(service_dicts(scan)):
                    http.append(prober.probe(http_target, port, scheme).as_dict())
            finally:
                if self._fingerprinter is None:
                    prober.close()
        return ServiceResult(target.address, scan, http, time.monotonic() - started)

    # --- przebieg ----------------------------------------------------------------

    def run(self, run_id: uuid.UUID) -> DiscoveryRun:
        session = self._session
        run = session.get(DiscoveryRun, run_id)
        if run is None:
            raise LookupError("Nie ma takiego przebiegu")
        settings = self._config.settings(run.settings)
        run.settings = {**asdict(settings), "http_paths": list(settings.http_paths)}
        parsed = parse_targets(list(run.targets))
        run.status = "running"
        run.started_at = utcnow()
        run.addresses_total = parsed.addresses
        session.commit()
        started = time.monotonic()
        observations: dict[str, Observation] = {}
        totals = {"batches_denied": 0, "batches_failed": 0, "hosts_failed": 0}
        sweep_seconds_per_address: list[float] = []

        def eta(remaining_addresses: int, pending_hosts: int) -> float:
            per_address = (
                sum(sweep_seconds_per_address) / len(sweep_seconds_per_address)
                if sweep_seconds_per_address
                else 0.05
            ) / max(1, settings.workers)
            return remaining_addresses * per_address + pending_hosts * 20.0 / settings.workers

        def stopped() -> bool:
            session.refresh(run, ["status"])
            return run.status == "stopping"

        queue = BatchQueue(parsed.networks)
        size = _power_of_two(settings.batch_initial, settings.batch_min, settings.batch_max)
        alive: list[DiscoveredHost] = [DiscoveredHost(ip=d, hostname=d) for d in parsed.domains]
        with ThreadPoolExecutor(max_workers=settings.workers) as pool:
            running: dict[Future[SweepResult], int] = {}
            while queue or running:
                while queue and len(running) < settings.workers and not stopped():
                    network = queue.take(size)
                    try:
                        scoped = self._guard.authorize_network(
                            str(network),
                            tool="nmap",
                            intrusiveness=Intrusiveness.LIGHT,
                            rule_name="discovery_sweep",
                            max_addresses=4096,
                        )
                    except ScopeError as error:
                        totals["batches_denied"] += 1
                        self._batch(
                            run, str(network), network.num_addresses, "denied", 0, 0, error.reason
                        )
                        run.addresses_done += network.num_addresses
                        session.commit()
                        continue
                    running[pool.submit(self._sweep, scoped, settings)] = network.num_addresses
                if not running:
                    break
                done, _ = wait(running, return_when=FIRST_COMPLETED)
                for future in done:
                    count = running.pop(future)
                    result = future.result()
                    status = "failed" if result.error else "done"
                    totals["batches_failed"] += bool(result.error)
                    self._batch(
                        run,
                        result.network.address,
                        count,
                        status,
                        len(result.hosts),
                        int(result.seconds * 1000),
                        result.error,
                    )
                    for host in result.hosts:
                        if host.ip not in observations:
                            observations[host.ip] = self._observe(run, host)
                            alive.append(host)
                    run.addresses_done += count
                    run.batches_done += 1
                    run.hosts_up = len(observations) + len(parsed.domains)
                    if not result.error and count:
                        per_address = result.seconds / count
                        sweep_seconds_per_address.append(result.seconds / count)
                        size = _power_of_two(
                            settings.batch_target_seconds / max(per_address, 1e-4),
                            settings.batch_min,
                            settings.batch_max,
                        )
                    run.eta_seconds = round(
                        eta(run.addresses_total - run.addresses_done, len(alive)), 1
                    )
                    session.commit()

            # Faza 2: usługi i HTTP na aktywnych hostach, też równolegle i przez bramę.
            pending: dict[Future[ServiceResult], str] = {}
            hosts = deque(alive)
            while hosts or pending:
                while hosts and len(pending) < settings.workers and not stopped():
                    host = hosts.popleft()
                    target_name = host.hostname if host.ip == host.hostname else host.ip
                    try:
                        target = self._guard.authorize(
                            target_name,
                            tool="nmap",
                            intrusiveness=Intrusiveness.LIGHT,
                            rule_name="discovery_services",
                        )
                        http_target = self._guard.authorize(
                            target_name,
                            tool="http_probe",
                            intrusiveness=Intrusiveness.LIGHT,
                            rule_name="discovery_http",
                        )
                    except ScopeError as error:
                        totals["hosts_failed"] += 1
                        self._batch(run, target_name, 1, "denied", 0, 0, error.reason, "services")
                        session.commit()
                        continue
                    if host.ip == host.hostname:  # domena: obserwacja pod adresem z DNS
                        observations.setdefault(
                            target.address,
                            self._observe(run, DiscoveredHost(target.address, host.hostname)),
                        )
                    pending[pool.submit(self._services, target, http_target, settings)] = (
                        target.address
                    )
                if not pending:
                    break
                done_services, _ = wait(pending, return_when=FIRST_COMPLETED)
                for service_future in done_services:
                    ip = pending.pop(service_future)
                    outcome = service_future.result()
                    observation = observations.get(ip)
                    if observation is not None and outcome.scan is not None:
                        observation.services = service_dicts(outcome.scan)
                        observation.http = outcome.http
                        observation.flags = flags_for(observation.hostname, outcome.http)
                    totals["hosts_failed"] += bool(outcome.error)
                    self._batch(
                        run,
                        ip,
                        1,
                        "failed" if outcome.error else "done",
                        1,
                        int(outcome.seconds * 1000),
                        outcome.error,
                        "services",
                    )
                    run.eta_seconds = round(eta(0, len(hosts) + len(pending)), 1)
                    session.commit()

        run.hosts_up = len(observations)
        run.duration_seconds = round(time.monotonic() - started, 2)
        run.eta_seconds = 0
        run.finished_at = utcnow()
        run.status = "stopped" if run.status == "stopping" else "done"
        run.summary = {
            **totals,
            "addresses_per_second": round(run.addresses_done / max(run.duration_seconds, 0.01), 1),
            "services": sum(len(o.services) for o in observations.values()),
            "web": sum(len(o.http) for o in observations.values()),
            "flags": sum(len(o.flags) for o in observations.values()),
            "target_errors": parsed.errors,
        }
        audit.record(
            session,
            audit.AuditEvent(
                actor=run.created_by,
                action="discovery_finished",
                reason=f"Przebieg discovery zakończony ({run.status})",
                inputs={"targets": run.targets[:20], **run.summary},
                object_type="discovery_run",
                object_id=str(run.id),
            ),
        )
        session.commit()
        return run

    def _observe(self, run: DiscoveryRun, host: DiscoveredHost) -> Observation:
        observation = Observation(run_id=run.id, ip=host.ip, hostname=host.hostname)
        self._session.add(observation)
        return observation

    def _batch(
        self,
        run: DiscoveryRun,
        target: str,
        addresses: int,
        status: str,
        hosts_up: int,
        duration_ms: int,
        detail: str | None,
        phase: str = "sweep",
    ) -> None:
        self._session.add(
            DiscoveryBatch(
                run_id=run.id,
                target=target[:64],
                addresses=addresses,
                phase=phase,
                status=status,
                hosts_up=hosts_up,
                duration_ms=duration_ms,
                detail=(detail or "")[:500] or None,
            )
        )


def latest_runs(session: Session, limit: int = 20) -> list[DiscoveryRun]:
    return list(
        session.scalars(select(DiscoveryRun).order_by(DiscoveryRun.created_at.desc()).limit(limit))
    )
