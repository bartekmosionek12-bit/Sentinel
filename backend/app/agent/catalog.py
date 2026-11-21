"""Zamknięta lista narzędzi serwera MCP. Model może wybierać wyłącznie z tej listy.

Poziom narzędzia jest stały i wynika z kodu, nie z planu: model nie może „obniżyć” poziomu
pełnego skanu, wpisując w plan L1.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.scope_guard import Intrusiveness


@dataclass(frozen=True)
class ToolSpec:
    name: str
    level: Intrusiveness
    description: str
    # Cel: pojedynczy host (IP albo nazwa) albo sieć CIDR (tylko odkrywanie, L1).
    target_kind: str = "host"
    # Narzędzie potrzebuje poświadczenia JIT (certyfikat SSH 15 min).
    needs_credentials: bool = False


CATALOG: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in (
        ToolSpec(
            "discover_hosts",
            Intrusiveness.LIGHT,
            "Które adresy w sieci odpowiadają (nmap -sn)",
            target_kind="network",
        ),
        ToolSpec(
            "scan_services",
            Intrusiveness.LIGHT,
            "Usługi i wersje na popularnych portach (nmap -sV, top 1000)",
        ),
        ToolSpec(
            "probe_http",
            Intrusiveness.LIGHT,
            "Nagłówek Server i tytuł strony WWW (jedno zapytanie GET)",
        ),
        ToolSpec(
            "scan_all_ports",
            Intrusiveness.INTRUSIVE,
            "Pełny skan portów 1–65535 z wersjami usług",
        ),
        ToolSpec(
            "verify_cve",
            Intrusiveness.INTRUSIVE,
            "Weryfikacja podatności szablonem nuclei z jawnej listy (bez eksploatacji)",
        ),
        ToolSpec(
            "collect_software_authenticated",
            Intrusiveness.INTRUSIVE,
            "Lista zainstalowanych pakietów przez SSH z certyfikatem na 15 minut (tylko odczyt)",
            needs_credentials=True,
        ),
    )
}


def tool(name: str) -> ToolSpec | None:
    return CATALOG.get(name)
