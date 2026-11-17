"""Polecenia administracyjne: `python -m app.cli <polecenie>`.

Polecenie `scan` i `seed-demo` trzeba uruchamiać w kontenerze `worker-scans`, bo tylko
on ma dostęp do sieci z celami skanowania.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.config import Settings, get_settings
from app.core.db import get_sessionmaker
from app.core.scope_guard import ScopeConfig
from app.feeds.base import FeedError, OfflineSource, as_utc
from app.feeds.service import FEEDS, sync_all
from app.inventory.service import import_assets, parse_assets_csv
from app.pipeline import analyze
from app.runtime import channel_sender, feed_source, get_rulebook, scan_service


def _out(text: str) -> None:
    sys.stdout.write(text + "\n")


def _print(data: Any) -> None:
    _out(json.dumps(data, ensure_ascii=False, indent=2, default=str))


class CliError(Exception):
    """Polecenia nie da się wykonać; komunikat trafia do użytkownika."""


def cmd_import_assets(session: Session, path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise CliError(f"Brak pliku {path}")
    rows, errors = parse_assets_csv(path.read_text(encoding="utf-8"))
    result = import_assets(session, rows, source=path.name, actor="cli")
    result.errors = errors
    return {
        "created": result.created,
        "updated": result.updated,
        "unchanged": result.unchanged,
        "errors": errors,
    }


def cmd_sync_feeds(session: Session, settings: Settings, directory: Path | None) -> dict[str, Any]:
    source = OfflineSource(directory) if directory else feed_source(session, settings)
    summary = sync_all(session, source, actor="cli")
    session.commit()
    report = analyze(session, get_rulebook(), channel_sender())
    return {"mode": source.mode, "feeds": summary.results, "analysis": report.summary()}


def cmd_fetch_feeds(session: Session, settings: Settings, out: Path) -> dict[str, Any]:
    """Pobiera snapshoty feedów do katalogu poza Gitem (wymaga internetu)."""
    from app.feeds.http import OnlineSource
    from app.models import Vulnerability

    online = feed_source(session, settings.model_copy(update={"feeds_mode": "online"}))
    if not isinstance(online, OnlineSource):
        raise CliError("Nie udało się przygotować źródła online")
    out.mkdir(parents=True, exist_ok=True)
    sizes: dict[str, int] = {}
    known = set(session.scalars(select(Vulnerability.cve_id)))
    for name in FEEDS:
        try:
            raw = online.load(name, cursor=None, cve_ids=sorted(known))
        except FeedError as error:
            raise CliError(f"Feed {name}: {error}") from error
        if name == "nvd":
            known |= {
                str(item.get("cve", {}).get("id"))
                for item in raw.get("vulnerabilities", [])
                if isinstance(item, dict)
            }
        target = out / f"{name}.json"
        target.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
        sizes[name] = target.stat().st_size
    return {"directory": str(out), "bytes": sizes}


def cmd_explain(session: Session, settings: Settings) -> dict[str, Any]:
    """Generuje z góry brakujące wyjaśnienia dla CVE z aktywnych zagrożeń (kolejno, lokalnie)."""
    from app.matching.engine import ACTIVE_STATUSES
    from app.models import Finding, Vulnerability
    from app.models.ops import AUDIENCES
    from app.runtime import explainer_service, local_provider

    provider = local_provider(settings)
    health = provider.health() if provider is not None else None
    if health is None or not health.available:
        detail = health.detail if health else "Model nie jest skonfigurowany (LLM_MODEL jest pusty)"
        return {"generated": 0, "skipped": detail}
    service = explainer_service(session)
    vulns = session.scalars(
        select(Vulnerability)
        .join(Finding, Finding.vulnerability_id == Vulnerability.id)
        .where(Finding.status.in_(ACTIVE_STATUSES))
        .distinct()
        .order_by(Vulnerability.cve_id)
    ).all()
    counts = {"cached": 0, "passed": 0, "rejected": 0, "unavailable": 0}
    for vuln in vulns:
        for audience in AUDIENCES:
            explanation = service.generate(vuln, audience, actor="cli:explain")
            counts["cached" if explanation.cached else explanation.validation] += 1
            session.commit()
    return {"model": health.model, "vulnerabilities": len(vulns), **counts}


def check_demo_preconditions(settings: Settings, scope: ScopeConfig) -> None:
    """seed-demo działa wyłącznie w trybie demo i wyłącznie na sieci demo-lab."""
    if not settings.demo_mode:
        raise CliError("seed-demo działa tylko przy DEMO_MODE=true w pliku .env (domyślnie false).")
    lab = settings.demo_lab_network
    if scope.allowed_domains or not scope.allowed_cidrs:
        raise CliError(
            "seed-demo wymaga zakresu ograniczonego do sieci demo-lab. "
            "Ustaw SCOPE_FILE=/app/rules/scope.demo.yaml."
        )
    for network in scope.allowed_cidrs:
        if network.version != lab.version or not network.subnet_of(lab):  # type: ignore[arg-type]
            raise CliError(
                f"Zakres zawiera sieć {network} spoza demo-lab ({lab}). seed-demo odmawia pracy."
            )


def cmd_seed_demo(session: Session, settings: Settings) -> dict[str, Any]:
    service = scan_service(session)
    check_demo_preconditions(settings, service.guard.config)
    expires = settings.demo_approval_expires_at
    approval_active = expires is not None and as_utc(expires) > datetime.now(UTC)
    audit.record(
        session,
        audit.AuditEvent(
            actor="seed_demo",
            action="seed_demo_approval" if approval_active else "seed_demo_started",
            reason=(
                "Zgoda seed_demo na akcje L2 wyłącznie w sieci demo-lab, do daty wygaśnięcia. "
                "Każda akcja nadal przechodzi przez scope_guard."
                if approval_active
                else "seed_demo bez aktywnej zgody: akcje L2 czekają na człowieka"
            ),
            inputs={
                "approval_source": "seed_demo",
                "demo_lab_cidr": settings.demo_lab_cidr,
                "expires_at": expires,
                "approval_active": approval_active,
            },
            object_type="scope",
        ),
    )
    assets = cmd_import_assets(session, settings.demo_assets_file)
    session.commit()
    has_snapshots = (settings.feeds_dir / "nvd.json").is_file()
    feeds_dir = settings.feeds_dir if has_snapshots else settings.demo_feeds_dir
    feeds = sync_all(session, OfflineSource(feeds_dir), actor="seed_demo")
    session.commit()
    run = service.run(trigger="seed_demo", actor="seed_demo")
    return {
        "assets": assets,
        "feeds_source": "pobrane snapshoty" if has_snapshots else "miniaturowy zestaw demo",
        "feeds": feeds.results,
        "l2_approval": "seed_demo" if approval_active else "wymaga człowieka",
        "scan": run.summary,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("import-assets", help="import zasobów z CSV").add_argument(
        "path", type=Path
    )
    commands.add_parser("sync-feeds", help="synchronizacja feedów i analiza").add_argument(
        "--dir", type=Path, default=None, help="katalog snapshotów (wymusza tryb offline)"
    )
    commands.add_parser("fetch-feeds", help="pobranie snapshotów feedów").add_argument(
        "--out", type=Path, required=True
    )
    commands.add_parser("scan", help="skan zakresu według reguł plannera")
    commands.add_parser("analyze", help="ponowne dopasowanie i ocena ryzyka")
    commands.add_parser("explain", help="wygenerowanie brakujących wyjaśnień modelem lokalnym")
    commands.add_parser("seed-demo", help="dane i skan demo-lab (tylko DEMO_MODE=true)")
    args = parser.parse_args(argv)

    settings = get_settings()
    with get_sessionmaker()() as session:
        try:
            if args.command == "import-assets":
                result: Any = cmd_import_assets(session, args.path)
            elif args.command == "sync-feeds":
                result = cmd_sync_feeds(session, settings, args.dir)
            elif args.command == "fetch-feeds":
                result = cmd_fetch_feeds(session, settings, args.out)
            elif args.command == "scan":
                run = scan_service(session).run(trigger="manual", actor="cli")
                result = run.summary
            elif args.command == "analyze":
                result = analyze(session, get_rulebook(), channel_sender()).summary()
            elif args.command == "explain":
                result = cmd_explain(session, settings)
            else:
                result = cmd_seed_demo(session, settings)
            session.commit()
        except CliError as error:
            session.rollback()
            sys.stderr.write(f"Błąd: {error}\n")
            return 2
    _print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
