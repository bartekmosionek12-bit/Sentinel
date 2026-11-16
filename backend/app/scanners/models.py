"""Ustrukturyzowane wyniki narzędzi skanujących (niezależne od narzędzia)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DiscoveredHost:
    ip: str
    hostname: str | None = None


@dataclass(frozen=True)
class ServiceInfo:
    port: int
    protocol: str
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpes: tuple[str, ...] = ()

    @property
    def banner(self) -> str:
        return " ".join(part for part in (self.product, self.version, self.extrainfo) if part)


@dataclass(frozen=True)
class HostScan:
    ip: str
    hostname: str | None = None
    services: tuple[ServiceInfo, ...] = field(default_factory=tuple)
