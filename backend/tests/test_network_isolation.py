"""Izolacja sieci w Compose (ARCHITECTURE §3, warstwa 2): kto fizycznie widzi demo-lab i OpenBao.

Stan po Etapie 5: do sieci z celami podłączone są tylko `worker-scans` (pipeline skanów, który
jeszcze nie przeszedł na MCP; ROADMAP) i `mcp-scanner` (agent). Agent, jego planista, LLM,
harness testu agenta, API i baza nie mają do celów żadnej drogi. Na żywo to samo sprawdza
`scripts/check_isolation.sh` w CI (próba połączenia TCP z każdego kontenera).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

COMPOSE = Path(__file__).resolve().parents[2] / "docker-compose.yml"
SCANNERS = {"worker-scans", "mcp-scanner"}
NO_TARGET_ACCESS = {
    "api",
    "db",
    "redis",
    "keycloak",
    "ollama",
    "worker-core",
    "worker-feeds",
    "worker-llm",
    "worker-agent",
    "worker-harness",
    "beat",
    "frontend",
    "openbao",
}


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    if not COMPOSE.exists():
        pytest.skip("docker-compose.yml poza drzewem testów")
    return dict(yaml.safe_load(COMPOSE.read_text(encoding="utf-8")))


def _networks(service: dict[str, Any]) -> set[str]:
    networks = service.get("networks") or []
    return set(networks if isinstance(networks, list) else networks.keys())


def test_only_scanners_and_lab_hosts_are_on_the_target_network(compose: dict[str, Any]) -> None:
    on_lab = {name for name, svc in compose["services"].items() if "demo-lab" in _networks(svc)}
    lab_hosts = {name for name in on_lab if name.startswith("lab-")}
    assert on_lab - lab_hosts == SCANNERS
    assert not (on_lab & NO_TARGET_ACCESS)
    assert compose["networks"]["demo-lab"]["internal"] is True


def test_agent_worker_reaches_targets_only_through_mcp(compose: dict[str, Any]) -> None:
    agent = _networks(compose["services"]["worker-agent"])
    assert "demo-lab" not in agent
    assert "vault" not in agent


def test_pipeline_scanner_has_no_credentials_or_model(compose: dict[str, Any]) -> None:
    scans = _networks(compose["services"]["worker-scans"])
    assert "vault" not in scans
    assert "llm" not in scans


def test_openbao_network_is_internal_and_small(compose: dict[str, Any]) -> None:
    on_vault = {name for name, svc in compose["services"].items() if "vault" in _networks(svc)}
    # api: wyłącznie kill switch (AppRole z polityką „tylko revoke-prefix”).
    assert on_vault == {"openbao", "bao-init", "mcp-scanner", "api"}
    assert compose["networks"]["vault"]["internal"] is True
