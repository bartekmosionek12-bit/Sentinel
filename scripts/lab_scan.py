#!/usr/bin/env python3
# ruff: noqa: T201  (skrypt konsolowy: wynik idzie na standardowe wyjście)
"""Test silnika discovery na labie od mentorów (lab.zip), bez stawiania całej aplikacji.

Uruchamia prawdziwy DiscoveryEngine (nmap + fingerprint HTTP + własne sygnatury) z
domyślną konfiguracją z rules/discovery.yaml. Zakres = dokładnie podane cele, więc
scope_guard wpuści tylko je. Wyniki zapisuje w lokalnej bazie SQLite, żeby kolejne
przebiegi dało się porównać (nowe, znikające, zmienione).

    python scripts/lab_scan.py lab.sqlite przebieg-1 127.0.0.1
    python scripts/lab_scan.py lab.sqlite przebieg-2 127.0.0.1 --compare

Wymaga nmap w PATH i zależności backendu (cd backend && uv sync).
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.core.scope_guard import ScopeConfig, ScopeGuard  # noqa: E402
from app.discovery.analysis import compare, host_states  # noqa: E402
from app.discovery.engine import DiscoveryConfig, DiscoveryEngine  # noqa: E402
from app.models.base import Base  # noqa: E402
from app.models.discovery import DiscoveryRun, Observation  # noqa: E402


class StderrAudit:
    """Decyzje scope_guard na stderr (w aplikacji trafiają do dziennika audytu)."""

    def __call__(self, *args: Any, **kwargs: Any) -> None:
        self.record(*args, **kwargs)

    def record(self, *args: Any, **kwargs: Any) -> None:
        print("audyt:", args, kwargs, file=sys.stderr)

    def __getattr__(self, name: str) -> Any:
        return lambda *a, **k: None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("db")
    parser.add_argument("name")
    parser.add_argument("targets", nargs="+")
    parser.add_argument("--compare", action="store_true", help="porównaj z poprzednim przebiegiem")
    args = parser.parse_args()

    engine = create_engine(f"sqlite+pysqlite:///{args.db}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    allow = [t if "/" in t else f"{t}/32" for t in args.targets]
    guard = ScopeGuard(
        ScopeConfig.from_dict(
            {"allow": {"cidrs": allow}, "rate_limits": {"default_per_minute": 600}}
        ),
        audit=StderrAudit(),
    )
    config = DiscoveryConfig.from_file(ROOT / "rules" / "discovery.yaml")
    with factory() as session:
        previous = session.scalars(
            select(DiscoveryRun)
            .where(DiscoveryRun.status == "done")
            .order_by(DiscoveryRun.created_at.desc())
        ).first()
        run = DiscoveryRun(id=uuid.uuid4(), name=args.name, targets=args.targets, settings={})
        session.add(run)
        session.commit()
        run = DiscoveryEngine(session, guard, config).run(run.id)
        hosts = session.scalars(select(Observation).where(Observation.run_id == run.id)).all()
        print(
            f"{run.name}: {run.status} {run.error or ''} czas {run.duration_seconds} s, "
            f"hosty {run.hosts_up}"
        )
        for host in sorted(hosts, key=lambda h: h.ip):
            services = [
                " ".join(
                    str(x)
                    for x in (f"{s['port']}/{s.get('name')}", s.get("product"), s.get("version"))
                    if x
                )
                for s in host.services
            ]
            print(f"\n{host.ip}: {', '.join(services) or 'brak usług'}")
            for http in host.http:
                names = [hit["name"] for hit in http.get("signatures") or []]
                print(
                    f"  {http.get('url')} {http.get('status')} {http.get('title')!r}\n"
                    f"    technologie: {', '.join(http.get('technologies') or []) or '-'}\n"
                    f"    sygnatury: {', '.join(names) or '-'}"
                )
            for flag in host.flags:
                print(f"  flaga: {flag['label']} (pewność {flag['confidence']})")
        if args.compare and previous is not None:
            diff = compare(session, previous.id, run.id)
            print(f"\nporównanie z przebiegiem {previous.name}: {diff['counts']}")
            for change in diff["changed_hosts"]:
                print(
                    " zmieniony",
                    change["ip"],
                    json.dumps(
                        {k: v for k, v in change.items() if k not in ("ip", "hostname")},
                        ensure_ascii=False,
                        default=str,
                    ),
                )
            for host in diff["new_hosts"]:
                print(" nowy", host["ip"], host["services"])
            for host in diff["gone_hosts"]:
                print(" znikający", host["ip"], host["services"])
            states = host_states(
                session, inactive_after=config.inactive_after_runs, window=config.window
            )
            print(" stany hostów:", {ip: v["state"] for ip, v in states.items()})
    return 0 if run.status == "done" else 1


if __name__ == "__main__":
    raise SystemExit(main())
