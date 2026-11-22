"""Warstwa 1: deterministyczny skan podatności narzędziami red team (nmap + skrypty NSE).

Te same cele i ten sam `rules/redteam.yaml` dają te same polecenia i te same reguły oceny:
żadnego modelu językowego, żadnej losowości. Wynik to lista podatności zgrupowanych po
rodzaju problemu (`group_key`), z dowodami z wyjścia narzędzia.

Bezpieczeństwo:
* przebieg startuje wyłącznie z ręcznego wywołania w API (bez harmonogramu i automatów),
* sieć do odkrycia hostów przechodzi przez `authorize_network` (L1), a każdy host przez
  `authorize` na poziomie L2 ze zgodą osoby, która uruchomiła przebieg,
* skrypty NSE tylko z `ALLOWED_SCRIPTS`: odczyt konfiguracji (handshake TLS, nagłówki,
  algorytmy SSH, tryb podpisywania SMB, logowanie anonimowe FTP). Bez exploitów,
  brute force i DoS; brak dopuszczenia kategorii `vuln`, `exploit`, `brute`, `dos`,
* kill switch blokuje start skanu hostów, a uruchomione procesy nmap przerywa wspólny
  rejestr procesów (`CANCELLATIONS`), tak jak w discovery.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from collections import Counter
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from pathlib import Path
from typing import Any

import yaml
from defusedxml import DefusedXmlException, ElementTree
from sqlalchemy.orm import Session

from app.agent.switch import is_killed
from app.core import audit
from app.core.scope_guard import (
    HumanApproval,
    Intrusiveness,
    ScopedTarget,
    ScopeError,
    ScopeGuard,
)
from app.matching.versions import parse_version
from app.models import RedteamFinding, RedteamRun
from app.models.base import utcnow
from app.scanners.nmap import NmapAdapter
from app.scanners.runner import SubprocessRunner, ToolError, ToolRunner

logger = logging.getLogger("sentinel.redteam")

ALLOWED_SCRIPTS = frozenset(
    {
        "ssl-cert",
        "ssl-enum-ciphers",
        "sslv2",
        "http-methods",
        "http-security-headers",
        "ssh2-enum-algos",
        "smb2-security-mode",
        "ftp-anon",
    }
)
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
WEAK_SSH = (
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group-exchange-sha1",
    "ssh-dss",
    "arcfour",
    "3des-cbc",
    "blowfish-cbc",
    "hmac-md5",
    "hmac-sha1-96",
)
OLD_TLS = ("SSLv3", "TLSv1.0", "TLSv1.1")
RISKY_METHODS = ("PUT", "DELETE", "TRACE", "CONNECT")
# Zawsze wykluczone w nuclei, niezależnie od rules/redteam.yaml: żadnej eksploatacji.
NUCLEI_ALWAYS_EXCLUDED = (
    "intrusive", "dos", "fuzz", "fuzzing", "lfi", "rfi", "rce", "sqli", "xss", "ssrf",
    "exploit", "bruteforce", "brute-force", "default-login", "token-spray", "dast",
    "headless", "oast", "file-upload", "deserialization", "injection",
)  # fmt: skip
NUCLEI_SEVERITIES = ("info", "low", "medium", "high", "critical")
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")


@dataclass(frozen=True)
class NucleiStep:
    enabled: bool = False
    templates_dir: str = "/opt/nuclei-templates"
    tags: tuple[str, ...] = ()
    severity: tuple[str, ...] = NUCLEI_SEVERITIES
    rate_limit: int = 5
    timeout_seconds: int = 300

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> NucleiStep:
        data = data or {}
        tags = tuple(str(t).lower() for t in data.get("tags") or ())
        bad = [t for t in tags if not _TAG_RE.match(t) or t in NUCLEI_ALWAYS_EXCLUDED]
        if bad:
            raise ValueError(f"nuclei: niedozwolone tagi w warstwie 1: {', '.join(bad)}")
        severity = tuple(str(s).lower() for s in data.get("severity") or NUCLEI_SEVERITIES)
        if set(severity) - set(NUCLEI_SEVERITIES):
            raise ValueError("nuclei: nieznany poziom ważności")
        return cls(
            enabled=bool(data.get("enabled", False)) and bool(tags),
            templates_dir=str(data.get("templates_dir", "/opt/nuclei-templates")),
            tags=tags,
            severity=severity,
            rate_limit=max(1, min(50, int(data.get("rate_limit", 5)))),
            timeout_seconds=int(data.get("timeout_seconds", 300)),
        )

    def args(self) -> list[str]:
        return [
            "-t", self.templates_dir,
            "-tags", ",".join(self.tags),
            "-etags", ",".join(NUCLEI_ALWAYS_EXCLUDED),
            "-severity", ",".join(self.severity),
            "-rate-limit", str(self.rate_limit),
            "-disable-update-check",
            "-no-interactsh",
            "-jsonl",
            "-silent",
        ]  # fmt: skip


@dataclass(frozen=True)
class Layer1Config:
    scripts: tuple[str, ...]
    ports: str
    timing: int = 3
    max_rate: int = 100
    workers: int = 4
    host_timeout_seconds: int = 300
    max_addresses: int = 1024
    exposed: dict[int, dict[str, str]] = field(default_factory=dict)
    min_versions: tuple[dict[str, str], ...] = ()
    cert_expiry_warning_days: int = 30
    nuclei: NucleiStep = field(default_factory=NucleiStep)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Layer1Config:
        scripts = tuple(str(s) for s in data.get("scripts") or ())
        unknown = sorted(set(scripts) - ALLOWED_SCRIPTS)
        if unknown:
            raise ValueError(f"Skrypty NSE spoza listy dozwolonych: {', '.join(unknown)}")
        if not re.fullmatch(r"[0-9,\-]+", str(data.get("ports", ""))):
            raise ValueError("ports: tylko liczby, przecinki i zakresy")
        return cls(
            scripts=scripts,
            ports=str(data["ports"]),
            timing=min(3, max(0, int(data.get("timing", 3)))),
            max_rate=max(1, int(data.get("max_rate", 100))),
            workers=max(1, min(16, int(data.get("workers", 4)))),
            host_timeout_seconds=int(data.get("host_timeout_seconds", 300)),
            max_addresses=int(data.get("max_addresses", 1024)),
            exposed={int(k): dict(v) for k, v in (data.get("exposed") or {}).items()},
            min_versions=tuple(dict(v) for v in data.get("min_versions") or ()),
            cert_expiry_warning_days=int(data.get("cert_expiry_warning_days", 30)),
            nuclei=NucleiStep.from_dict(data.get("nuclei")),
        )

    @classmethod
    def from_file(cls, path: Path) -> Layer1Config:
        return cls.from_dict(yaml.safe_load(path.read_text(encoding="utf-8")) or {})


@dataclass(frozen=True)
class PortResult:
    port: int
    protocol: str
    name: str = ""
    product: str = ""
    version: str = ""
    tunnel: str = ""
    scripts: dict[str, str] = field(default_factory=dict)
    # Elementy <elem key="..."> skryptu spłaszczone do listy wartości (kolejność z XML).
    elems: dict[str, dict[str, list[str]]] = field(default_factory=dict)


@dataclass(frozen=True)
class Hit:
    check: str
    title: str
    severity: str
    category: str
    port: PortResult
    evidence: tuple[str, ...]
    variant: str = ""  # np. produkt przy przestarzałej wersji

    @property
    def group_key(self) -> str:
        return f"{self.check}:{self.variant}" if self.variant else self.check


def parse_scan_xml(xml: str) -> dict[str, list[PortResult]]:
    """`nmap -sV --script ... -oX -` → otwarte porty z wynikami skryptów, per adres."""
    try:
        root = ElementTree.fromstring(xml)
    except (ElementTree.ParseError, DefusedXmlException) as error:
        raise ToolError(f"nmap: nieprawidłowy XML ({error!r})") from error
    if root.tag != "nmaprun":
        raise ToolError("nmap: nieoczekiwany format wyniku")
    hosts: dict[str, list[PortResult]] = {}
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = next(
            (a.get("addr", "") for a in host.findall("address") if a.get("addrtype") != "mac"),
            "",
        )
        ports: list[PortResult] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            attrs = dict(service.attrib) if service is not None else {}
            scripts: dict[str, str] = {}
            elems: dict[str, dict[str, list[str]]] = {}
            for script in port.findall("script"):
                sid = script.get("id", "")
                scripts[sid] = script.get("output", "")
                flat: dict[str, list[str]] = {}
                for elem in script.iter("elem"):
                    flat.setdefault(elem.get("key", ""), []).append((elem.text or "").strip())
                elems[sid] = flat
            ports.append(
                PortResult(
                    port=int(port.get("portid", "0")),
                    protocol=port.get("protocol", "tcp"),
                    name=attrs.get("name", ""),
                    product=attrs.get("product", ""),
                    version=attrs.get("version", ""),
                    tunnel=attrs.get("tunnel", ""),
                    scripts=scripts,
                    elems=elems,
                )
            )
        if ip:
            hosts[ip] = ports
    return hosts


def _date(value: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value.strip()[:19], fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def evaluate(port: PortResult, config: Layer1Config, now: datetime) -> list[Hit]:
    """Reguły oceny jednego portu. Kolejność i treść wyniku zależą wyłącznie od danych."""
    hits: list[Hit] = []

    def hit(
        check: str, title: str, severity: str, category: str, *evidence: str, variant: str = ""
    ) -> None:
        hits.append(
            Hit(check, title, severity, category, port, tuple(e for e in evidence if e), variant)
        )

    exposed = config.exposed.get(port.port)
    if exposed and not (port.port == 21 and port.tunnel == "ssl"):
        hit(
            exposed["check"],
            exposed["title"],
            exposed["severity"],
            exposed["category"],
            f"Port {port.port}/{port.protocol} otwarty: {port.name} {port.product} "
            f"{port.version}".strip(),
        )

    banner = f"{port.product} {port.version}".strip()
    for rule in config.min_versions:
        product = rule["product"].lower()
        if product and product in port.product.lower():
            current, minimum = (
                parse_version(port.version.split()[0] if port.version else None),
                parse_version(str(rule["min"])),
            )
            if current is not None and minimum is not None and current < minimum:
                hit(
                    "outdated_software",
                    f"Przestarzała wersja: {port.product}",
                    rule.get("severity", "medium"),
                    "aktualizacje",
                    f"Wykryto {banner}, minimalna bezpieczna wersja w regułach: {rule['min']}",
                    variant=product.replace(" ", "-"),
                )

    output = port.scripts
    if "sslv2" in output and "SSLv2 supported" in output["sslv2"]:
        hit("tls_sslv2", "Włączony SSLv2", "high", "kryptografia", output["sslv2"][:300])
    ciphers = output.get("ssl-enum-ciphers", "")
    if ciphers:
        old = [p for p in OLD_TLS if re.search(rf"^\s*{re.escape(p)}:", ciphers, re.MULTILINE)]
        if old:
            hit(
                "tls_old_protocol",
                "Przestarzałe protokoły TLS",
                "medium",
                "kryptografia",
                "Serwer przyjmuje: " + ", ".join(old),
            )
        grade = re.search(r"least strength:\s*([A-F])", ciphers)
        if grade and grade.group(1) in "CDEF":
            hit(
                "tls_weak_cipher",
                "Słabe szyfry TLS",
                "medium",
                "kryptografia",
                f"Najsłabszy zestaw szyfrów: klasa {grade.group(1)} (ssl-enum-ciphers)",
            )
    cert = port.elems.get("ssl-cert", {})
    if cert:
        not_after = _date((cert.get("notAfter") or [""])[0])
        if not_after is not None and not_after < now:
            hit(
                "cert_expired",
                "Wygasły certyfikat TLS",
                "medium",
                "kryptografia",
                f"Ważny do {not_after.date().isoformat()}",
            )
        elif not_after is not None and not_after < now + timedelta(
            days=config.cert_expiry_warning_days
        ):
            hit(
                "cert_expiring",
                "Certyfikat TLS wkrótce wygaśnie",
                "low",
                "kryptografia",
                f"Ważny do {not_after.date().isoformat()}",
            )
        text = output.get("ssl-cert", "")
        issuer = re.search(r"Issuer: (.*)", text)
        subject = re.search(r"Subject: (.*)", text)
        if issuer and subject and issuer.group(1).strip() == subject.group(1).strip():
            hit(
                "cert_self_signed",
                "Certyfikat TLS z podpisem własnym",
                "low",
                "kryptografia",
                f"Subject = Issuer: {subject.group(1).strip()[:120]}",
            )
    methods = output.get("http-methods", "")
    risky = re.search(r"Potentially risky methods:\s*(.+)", methods)
    if risky:
        found = [m for m in RISKY_METHODS if m in risky.group(1).split()]
        if found:
            hit(
                "http_risky_methods",
                "Ryzykowne metody HTTP",
                "medium",
                "konfiguracja",
                "Serwer deklaruje: " + " ".join(found),
            )
    headers = output.get("http-security-headers", "")
    if (
        headers
        and (port.tunnel == "ssl" or port.name == "https" or port.port == 443)
        # nmap pisze „HSTS not configured in HTTPS Server” pod kluczem nagłówka.
        and ("Strict_Transport_Security" not in headers or "HSTS not configured" in headers)
    ):
        hit(
            "http_missing_hsts",
            "Brak nagłówka HSTS",
            "low",
            "konfiguracja",
            "Odpowiedź HTTPS bez Strict-Transport-Security",
        )
    ssh = output.get("ssh2-enum-algos", "")
    if ssh:
        weak = sorted(
            {w for w in WEAK_SSH for line in ssh.splitlines() if line.strip().startswith(w)}
        )
        if weak:
            hit(
                "ssh_weak_algorithms",
                "Słabe algorytmy SSH",
                "low",
                "kryptografia",
                "Serwer oferuje: " + ", ".join(weak),
            )
    smb = output.get("smb2-security-mode", "")
    if "not required" in smb:
        hit(
            "smb_signing_not_required",
            "Podpisywanie SMB nie jest wymagane",
            "medium",
            "konfiguracja",
            smb.strip()[:200],
        )
    ftp = output.get("ftp-anon", "")
    if "Anonymous FTP login allowed" in ftp:
        hit(
            "ftp_anonymous",
            "Anonimowe logowanie FTP",
            "high",
            "uwierzytelnianie",
            ftp.strip().splitlines()[0][:200],
        )
    return hits


WEB_NAMES = ("http", "https", "http-proxy", "http-alt", "ssl/http")


def is_web(port: PortResult) -> bool:
    return port.protocol == "tcp" and (
        port.name in WEB_NAMES
        or port.name.startswith("http")
        or (port.tunnel == "ssl" and port.port in (443, 8443, 9443))
    )


def parse_nuclei(output: str) -> list[dict[str, str]]:
    """Wynik `nuclei -jsonl`. Ważność spoza listy traktujemy jako `info`."""
    found: list[dict[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError as error:
            raise ToolError("nuclei: wynik nie jest JSON-em") from error
        info = item.get("info") or {}
        severity = str(info.get("severity", "info")).lower()
        found.append(
            {
                "template": str(item.get("template-id", ""))[:100],
                "name": str(info.get("name", "")),
                "severity": severity if severity in NUCLEI_SEVERITIES else "info",
                "matched": str(item.get("matched-at", ""))[:300],
                "extracted": ", ".join(str(v) for v in item.get("extracted-results") or ())[:300],
            }
        )
    return found


def nmap_args(config: Layer1Config) -> list[str]:
    return [
        "-sV",
        "-Pn",
        "-n",
        f"-T{config.timing}",
        "--max-rate",
        str(config.max_rate),
        "-p",
        config.ports,
        "--open",
        "--script",
        ",".join(config.scripts),
        "-oX",
        "-",
    ]


def expand_targets(items: Sequence[str]) -> tuple[list[str], list[str]]:
    """Adresy IP i podsieci CIDR. Domeny i inne napisy wracają jako błędy."""
    networks: list[str] = []
    errors: list[str] = []
    for raw in items:
        value = raw.strip()
        if not value:
            continue
        try:
            networks.append(str(ip_network(value, strict=False)))
        except ValueError:
            errors.append(f"{value[:80]}: warstwa 1 przyjmuje adres IP albo podsieć CIDR")
    return list(dict.fromkeys(networks)), errors


@dataclass
class HostOutcome:
    ip: str
    hits: list[Hit] = field(default_factory=list)
    log: dict[str, Any] = field(default_factory=dict)
    ports: list[PortResult] = field(default_factory=list)


class Layer1Scanner:
    def __init__(
        self,
        session: Session,
        guard: ScopeGuard,
        config: Layer1Config,
        *,
        runner: ToolRunner | None = None,
        now: datetime | None = None,
    ) -> None:
        self._session = session
        self._guard = guard
        self._config = config
        self._runner = runner or SubprocessRunner()
        self._nmap = NmapAdapter(self._runner)
        self._now = now

    def _hosts(self, run: RedteamRun) -> tuple[list[str], list[dict[str, Any]]]:
        hosts: list[str] = []
        log: list[dict[str, Any]] = []
        networks, errors = expand_targets(run.targets)
        log += [{"step": "cele", "error": e} for e in errors]
        for cidr in networks:
            network = ip_network(cidr)
            if network.num_addresses == 1:
                hosts.append(str(network.network_address))
                continue
            try:
                scoped = self._guard.authorize_network(
                    cidr,
                    tool="nmap",
                    intrusiveness=Intrusiveness.LIGHT,
                    rule_name="redteam_layer1_discovery",
                    max_addresses=self._config.max_addresses,
                )
            except ScopeError as error:
                log.append({"step": "odkrywanie", "target": cidr, "error": error.reason})
                continue
            started = time.monotonic()
            found = self._nmap.discover_batch(
                scoped,
                ports=self._config.ports,
                timing=self._config.timing,
                max_rate=self._config.max_rate,
            )
            hosts += [h.ip for h in found]
            log.append(
                {
                    "step": "odkrywanie",
                    "target": cidr,
                    "tool": "nmap -sn",
                    "hosts_up": len(found),
                    "duration_ms": int((time.monotonic() - started) * 1000),
                }
            )
        return list(dict.fromkeys(hosts)), log

    def _authorize(
        self, ip: str, tool: str, rule: str, approval: HumanApproval
    ) -> ScopedTarget | str:
        """Decyzja scope_guard (L2 ze zgodą wywołującego). Zawsze w wątku głównym:
        zapis audytu idzie jedną sesją, a kolejność decyzji jest stała."""
        try:
            return self._guard.authorize(
                ip,
                tool=tool,
                intrusiveness=Intrusiveness.INTRUSIVE,
                rule_name=rule,
                approval=approval,
            )
        except ScopeError as error:
            return error.reason

    def _nmap_host(self, target: ScopedTarget, now: datetime) -> HostOutcome:
        ip = target.address
        outcome = HostOutcome(ip)
        started = time.monotonic()
        try:
            output = self._runner.run(
                "nmap",
                nmap_args(self._config),
                target,
                timeout=self._config.host_timeout_seconds,
            )
            ports = parse_scan_xml(output.stdout).get(ip, [])
        except ToolError as error:
            outcome.log = {"step": "skan", "target": ip, "error": str(error)[:300]}
            return outcome
        outcome.ports = sorted(ports, key=lambda p: (p.protocol, p.port))
        for port in outcome.ports:
            outcome.hits += evaluate(port, self._config, now)
        outcome.log = {
            "step": "skan",
            "target": ip,
            "tool": "nmap -sV --script " + ",".join(self._config.scripts),
            "open_ports": [
                f"{p.port}/{p.protocol} {p.name} {p.product} {p.version}".strip()
                for p in outcome.ports
            ],
            "scripts": {
                f"{p.port}/{s}": out[:600] for p in outcome.ports for s, out in p.scripts.items()
            },
            "findings": len(outcome.hits),
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        return outcome

    def _nuclei_host(self, outcome: HostOutcome, target: ScopedTarget) -> list[dict[str, Any]]:
        """nuclei na każdym porcie HTTP(S) z wyniku nmap. Bez binarki: jawna adnotacja w logu."""
        step = self._config.nuclei
        log: list[dict[str, Any]] = []
        for port in (p for p in outcome.ports if is_web(p)):
            try:
                output = self._runner.run(
                    "nuclei", step.args(), target, timeout=step.timeout_seconds, port=port.port
                )
            except ToolError as error:
                log.append({"port": port.port, "skipped": f"nuclei pominięty: {str(error)[:200]}"})
                if str(error).startswith("Brak narzędzia"):
                    break  # brak binarki: nie próbujemy kolejnych portów
                continue
            matches = parse_nuclei(output.stdout)
            for match in matches:
                outcome.hits.append(
                    Hit(
                        check="nuclei",
                        title=match["name"][:200] or match["template"],
                        severity=match["severity"],
                        category="nuclei",
                        port=port,
                        evidence=tuple(e for e in (match["matched"], match["extracted"]) if e),
                        variant=match["template"],
                    )
                )
            log.append({"port": port.port, "matches": len(matches)})
        return log

    def _scan_hosts(
        self, hosts: Sequence[str], approval: HumanApproval, now: datetime, log: list[Any]
    ) -> list[HostOutcome]:
        session = self._session
        outcomes: list[HostOutcome] = []
        with ThreadPoolExecutor(max_workers=self._config.workers) as pool:
            # Faza 1: nmap. Zgody scope_guard w wątku głównym, same skany równolegle.
            futures = []
            for ip in hosts:
                if is_killed(session):
                    log.append({"step": "skan", "error": "Kill switch: przebieg zatrzymany"})
                    break
                target = self._authorize(ip, "nmap", "redteam_layer1", approval)
                if isinstance(target, str):
                    outcomes.append(
                        HostOutcome(ip, log={"step": "skan", "target": ip, "error": target})
                    )
                    continue
                futures.append(pool.submit(self._nmap_host, target, now))
            outcomes += [f.result() for f in futures]
            # Faza 2: nuclei na portach HTTP(S) wykrytych w fazie 1.
            step = self._config.nuclei
            web = [o for o in outcomes if step.enabled and any(is_web(p) for p in o.ports)]
            pending = []
            for outcome in web:
                if is_killed(session):
                    break
                target = self._authorize(outcome.ip, "nuclei", "redteam_layer1_nuclei", approval)
                if isinstance(target, str):
                    outcome.log["nuclei"] = [{"error": target}]
                    continue
                pending.append((outcome, pool.submit(self._nuclei_host, outcome, target)))
            for outcome, future in pending:
                outcome.log["nuclei"] = future.result()
                outcome.log["findings"] = len(outcome.hits)
        return outcomes

    def run(self, run_id: uuid.UUID) -> RedteamRun:
        session = self._session
        run = session.get(RedteamRun, run_id)
        if run is None:
            raise LookupError("Nie ma takiego przebiegu warstwy 1")
        if run.status != "queued":
            return run
        run.status = "running"
        run.started_at = utcnow()
        session.commit()
        now = self._now or utcnow()
        approval = HumanApproval(approved_by=run.requested_by, reason=run.reason)
        try:
            hosts, log = self._hosts(run)
            outcomes = self._scan_hosts(hosts, approval, now, log)
            for outcome in sorted(outcomes, key=lambda o: _ip_key(o.ip)):
                log.append(outcome.log)
                for item in outcome.hits:
                    session.add(
                        RedteamFinding(
                            run_id=run.id,
                            check_id=item.check,
                            group_key=item.group_key,
                            title=item.title,
                            severity=item.severity,
                            category=item.category,
                            ip=outcome.ip,
                            port=item.port.port,
                            protocol=item.port.protocol,
                            service=(item.port.name or "")[:64],
                            tool="nuclei" if item.check == "nuclei" else "nmap",
                            evidence=list(item.evidence),
                        )
                    )
            hits = [h for o in outcomes for h in o.hits]
            run.hosts = len(hosts)
            run.log = log
            run.summary = {
                "hosts": len(hosts),
                "findings": len(hits),
                "groups": len({h.group_key for h in hits}),
                "by_severity": dict(Counter(h.severity for h in hits)),
                "errors": sum(1 for entry in log if entry.get("error")),
            }
            run.status = "done"
        except Exception as error:  # zapisujemy przyczynę; worker nie może zostawić „running”
            logger.exception("redteam_layer1_failed")
            run.status = "failed"
            run.error = str(error)[:500]
        run.finished_at = utcnow()
        audit.record(
            session,
            audit.AuditEvent(
                actor=run.requested_by,
                action="redteam_layer1_finished",
                reason=f"Warstwa 1: {run.status}",
                inputs={"summary": run.summary, "error": run.error},
                object_type="redteam_run",
                object_id=str(run.id),
            ),
        )
        session.commit()
        return run


def _ip_key(ip: str) -> tuple[int, int]:
    address = ip_network(ip).network_address
    return (address.version, int(address))
