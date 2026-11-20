"""CLI: warunki seed-demo i import zasobów."""

from __future__ import annotations

from ipaddress import ip_address
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session

from app.cli import CliError, check_demo_preconditions, cmd_import_assets, cmd_sync_feeds
from app.core.config import Settings
from app.core.scope_guard import ScopeConfig
from tests.pipeline_helpers import ASSETS_CSV, FEEDS_DIR, RULES

LAB_SCOPE = ScopeConfig.from_file(RULES / "scope.demo.yaml")


def _settings(**values: Any) -> Settings:
    return Settings(_env_file=None, RULES_DIR=str(RULES), **values)


def test_demo_scope_file_allows_only_the_lab_and_denies_gateway_and_scanner() -> None:
    lab = _settings().demo_lab_network
    assert [str(n) for n in LAB_SCOPE.allowed_cidrs] == [str(lab)]
    assert LAB_SCOPE.allowed_domains == ()
    assert {str(n) for n in LAB_SCOPE.denied_cidrs} == {"172.30.99.1/32", "172.30.99.250/32"}
    check_demo_preconditions(_settings(DEMO_MODE="true"), LAB_SCOPE)


def test_seed_demo_refuses_without_demo_mode() -> None:
    with pytest.raises(CliError, match="DEMO_MODE=true"):
        check_demo_preconditions(_settings(), LAB_SCOPE)


@pytest.mark.parametrize(
    "scope",
    [
        {},
        {"allow": {"cidrs": ["172.30.99.0/24", "10.0.0.0/24"]}},
        {"allow": {"cidrs": ["172.30.0.0/16"]}},
        {"allow": {"cidrs": ["172.30.99.0/24"], "domains": ["example.com"]}},
    ],
)
def test_seed_demo_refuses_any_scope_wider_than_the_lab(scope: dict[str, Any]) -> None:
    with pytest.raises(CliError, match="demo-lab"):
        check_demo_preconditions(_settings(DEMO_MODE="true"), ScopeConfig.from_dict(scope))


def test_import_assets_reports_row_errors(session: Session, tmp_path: Path) -> None:
    path = tmp_path / "assets.csv"
    path.write_text(ASSETS_CSV + "zły,router,,internal,3,,\n", encoding="utf-8")
    result = cmd_import_assets(session, path)
    assert result["created"] == 3
    assert len(result["errors"]) == 1
    with pytest.raises(CliError, match="Brak pliku"):
        cmd_import_assets(session, tmp_path / "nie-ma.csv")


def test_demo_assets_file_is_valid() -> None:
    from app.inventory.service import parse_assets_csv

    text = (RULES.parent / "demo-lab" / "assets.csv").read_text(encoding="utf-8")
    rows, errors = parse_assets_csv(text)
    assert errors == []
    lab = _settings().demo_lab_network
    assert rows
    assert all(r["address"] and ip_address(r["address"]) in lab for r in rows)


def test_sync_feeds_offline_then_analysis(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RULES_DIR", str(RULES))
    from app.core.config import get_settings
    from app.runtime import get_rulebook

    get_settings.cache_clear()
    get_rulebook.cache_clear()
    try:
        result = cmd_sync_feeds(session, _settings(), FEEDS_DIR)
    finally:
        get_settings.cache_clear()
        get_rulebook.cache_clear()
    assert result["mode"] == "offline"
    assert result["feeds"]["nvd"]["status"] == "ok"
    assert result["analysis"]["findings_created"] == 0


def test_explain_without_model_skips_and_keeps_working(session: Session) -> None:
    from app.cli import cmd_explain

    result = cmd_explain(session, _settings())
    assert result["generated"] == 0
    assert "LLM_MODEL" in result["skipped"]


def test_inject_kev_refuses_without_demo_mode(session: Session) -> None:
    from app.cli import cmd_inject_kev

    with pytest.raises(CliError, match="DEMO_MODE=true"):
        cmd_inject_kev(session, _settings(), "CVE-2021-23017")


def test_inject_kev_in_demo_mode_reports_timings(session: Session) -> None:
    from app.cli import cmd_inject_kev
    from app.pipeline import analyze
    from app.runtime import get_rulebook
    from tests.pipeline_helpers import seed_feeds, seed_inventory

    seed_feeds(session)
    seed_inventory(session)
    analyze(session, get_rulebook())
    result = cmd_inject_kev(session, _settings(DEMO_MODE="true"), "cve-2021-23017")
    assert result["report"]["title"] == "Zero-day: CVE-2021-23017"
    assert result["timings_ms"]["total"] < 5000
    assert result["model_summary_queued"] is False
    with pytest.raises(CliError, match="już jest"):
        cmd_inject_kev(session, _settings(DEMO_MODE="true"), "CVE-2021-23017")
