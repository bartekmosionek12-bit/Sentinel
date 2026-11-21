"""Adapter nmap: odkrywanie hostów w sieci i wykrywanie wersji usług (-sV).

Poziom inwazyjności L1. Bez skryptów NSE, bez wykrywania systemu, bez uprawnień roota
(nmap sam przechodzi wtedy na skan połączeniowy).
"""

from __future__ import annotations

from collections.abc import Sequence

from defusedxml import DefusedXmlException, ElementTree

from app.core.scope_guard import Intrusiveness, ScopedNetwork, ScopedTarget
from app.scanners.models import DiscoveredHost, HostScan, ServiceInfo
from app.scanners.runner import SubprocessRunner, ToolError, ToolRunner
from app.scanners.top_ports import TOP_1000_TCP

DISCOVERY_PORTS = "22,80,443,3000,3306,5432,6379,8080,8443"
TOP_1000_ALIAS = "top-1000"
DEFAULT_PORTS = TOP_1000_ALIAS


def parse_nmap_xml(xml: str) -> list[HostScan]:
    """Parsuje wynik `nmap -oX -`. Zwraca tylko hosty w stanie „up” i porty „open”."""
    try:
        root = ElementTree.fromstring(xml)
    except (ElementTree.ParseError, DefusedXmlException) as error:
        raise ToolError(f"nmap: nieprawidłowy XML ({error!r})") from error
    if root.tag != "nmaprun":
        raise ToolError("nmap: nieoczekiwany format wyniku")
    hosts: list[HostScan] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = next(
            (
                a.get("addr", "")
                for a in host.findall("address")
                if a.get("addrtype") in {"ipv4", "ipv6"}
            ),
            "",
        )
        if not ip:
            continue
        hostname_el = host.find("hostnames/hostname")
        services: list[ServiceInfo] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            cpes: tuple[str, ...] = ()
            attrs: dict[str, str] = {}
            if service is not None:
                attrs = dict(service.attrib)
                cpes = tuple(c.text.strip() for c in service.findall("cpe") if c.text)
            services.append(
                ServiceInfo(
                    port=int(port.get("portid", "0")),
                    protocol=port.get("protocol", "tcp"),
                    name=attrs.get("name", ""),
                    product=attrs.get("product", ""),
                    version=attrs.get("version", ""),
                    extrainfo=attrs.get("extrainfo", ""),
                    cpes=cpes,
                )
            )
        hosts.append(
            HostScan(
                ip=ip,
                hostname=hostname_el.get("name") if hostname_el is not None else None,
                services=tuple(services),
            )
        )
    return hosts


def _parse_ranges(spec: str) -> list[tuple[int, int]]:
    ranges = []
    for token in spec.split(","):
        first, _, last = token.partition("-")
        if not first.isdigit() or (last and not last.isdigit()) or token.endswith("-"):
            raise ToolError("nmap: nieprawidłowa lista portów")
        low, high = int(first), int(last or first)
        if not 1 <= low <= high <= 65535:
            raise ToolError("nmap: nieprawidłowa lista portów")
        ranges.append((low, high))
    return ranges


def expand_ports(ports: str) -> str:
    """Rozwija specyfikację portów do postaci dla `nmap -p`.

    Elementy oddzielone przecinkami: port, zakres albo `top-1000`. Wynik jest sumą
    wszystkich elementów (posortowaną, ze scalonymi zakresami), więc `top-1000,6379`
    oznacza listę nmap „top 1000” powiększoną o port 6379, a nie zastąpioną nim.
    """
    ranges: list[tuple[int, int]] = []
    for part in ports.split(","):
        ranges += _parse_ranges(TOP_1000_TCP if part == TOP_1000_ALIAS else part)
    merged: list[tuple[int, int]] = []
    for low, high in sorted(ranges):
        if merged and low <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], high))
        else:
            merged.append((low, high))
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in merged)


def _port_args(ports: str) -> list[str]:
    return ["-p", expand_ports(ports)]


class NmapAdapter:
    binary = "nmap"

    def __init__(self, runner: ToolRunner | None = None) -> None:
        self._runner = runner or SubprocessRunner()

    def discover(self, network: ScopedNetwork, *, timeout: float = 120) -> list[DiscoveredHost]:
        if not isinstance(network, ScopedNetwork):
            raise TypeError("nmap.discover przyjmuje wyłącznie ScopedNetwork")
        if network.intrusiveness > Intrusiveness.LIGHT:
            raise ToolError("nmap: odkrywanie hostów działa tylko na poziomie L1")
        args = ["-sn", "-n", f"-PS{DISCOVERY_PORTS}", "-T4", "-oX", "-"]
        if network.excluded:
            args += ["--exclude", ",".join(str(n) for n in network.excluded)]
        output = self._runner.run(self.binary, args, network, timeout=timeout)
        return [DiscoveredHost(ip=h.ip, hostname=h.hostname) for h in parse_nmap_xml(output.stdout)]

    def scan_services(
        self, target: ScopedTarget, *, ports: str = DEFAULT_PORTS, timeout: float = 300
    ) -> HostScan:
        if not isinstance(target, ScopedTarget):
            raise TypeError("nmap.scan_services przyjmuje wyłącznie ScopedTarget")
        args: Sequence[str] = ["-sV", "-Pn", "-n", "-T4", *_port_args(ports), "--open", "-oX", "-"]
        output = self._runner.run(self.binary, args, target, timeout=timeout)
        for host in parse_nmap_xml(output.stdout):
            if host.ip == target.address:
                return HostScan(ip=host.ip, hostname=target.hostname, services=host.services)
        return HostScan(ip=target.address, hostname=target.hostname)
