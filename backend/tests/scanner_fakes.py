"""Fałszywy runner narzędzi: zwraca przygotowany XML i zapisuje wywołania."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from app.core.scope_guard import ScopedNetwork, ScopedTarget
from app.scanners.models import ServiceInfo
from app.scanners.runner import ToolOutput, build_argv

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class FakeRunner:
    def __init__(self, respond: Callable[[tuple[str, ...]], str]) -> None:
        self._respond = respond
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        binary: str,
        args: Sequence[str],
        target: ScopedTarget | ScopedNetwork,
        *,
        timeout: float,
    ) -> ToolOutput:
        argv = build_argv(binary, args, target)
        self.calls.append(argv)
        return ToolOutput(self._respond(argv), "", 0, argv)


def services_xml(ip: str, services: Sequence[ServiceInfo]) -> str:
    """Buduje wynik `nmap -sV -oX` dla jednego hosta."""
    ports = []
    for s in services:
        attrs = f'name="{s.name}"'
        if s.product:
            attrs += f' product="{s.product}"'
        if s.version:
            attrs += f' version="{s.version}"'
        if s.extrainfo:
            attrs += f' extrainfo="{s.extrainfo}"'
        cpes = "".join(f"<cpe>{c}</cpe>" for c in s.cpes)
        ports.append(
            f'<port protocol="{s.protocol}" portid="{s.port}"><state state="open"/>'
            f"<service {attrs}>{cpes}</service></port>"
        )
    return (
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        f'<address addr="{ip}" addrtype="ipv4"/><ports>{"".join(ports)}</ports></host></nmaprun>'
    )


def discovery_xml(ips: Sequence[str]) -> str:
    hosts = "".join(
        f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/></host>' for ip in ips
    )
    return f'<?xml version="1.0"?><nmaprun>{hosts}</nmaprun>'


class FakeLab:
    """Udaje sieć demo-lab: odpowiada na odkrywanie i skan usług z podanej mapy."""

    def __init__(self, services: Mapping[str, Sequence[ServiceInfo]]) -> None:
        self.services: dict[str, Sequence[ServiceInfo]] = dict(services)
        self.extra_ports: dict[str, Sequence[ServiceInfo]] = {}
        self.runner = FakeRunner(self._respond)

    def _respond(self, argv: tuple[str, ...]) -> str:
        target = argv[-1]
        if "-sn" in argv:
            return discovery_xml(sorted(self.services))
        found = list(self.services.get(target, ()))
        if "1-65535" in argv:
            found += list(self.extra_ports.get(target, ()))
        return services_xml(target, found)
