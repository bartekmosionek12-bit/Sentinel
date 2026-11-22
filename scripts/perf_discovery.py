"""Pomiar skali discovery na prawdziwym nmapie w laboratorium scripts/perf_lab.sh.

Uruchamia zwykły DiscoveryEngine (scope_guard, adaptacyjne paczki, równoległe workery,
ponowna próba, skan usług i fingerprint HTTP) na zakresie 10.200.0.0/18 (16 384 adresy)
w przestrzeni nazw asi-lab. Baza: SQLite w pliku tymczasowym. Wynik: JSON z czasami.

    sudo scripts/perf_lab.sh up 48
    sudo ip netns exec asi-lab env PYTHONPATH=backend python scripts/perf_discovery.py [workers]
    sudo scripts/perf_lab.sh down
"""

from __future__ import annotations

import json
import resource
import sys
import tempfile
import time
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    from app.core.audit import DbAuditSink
    from app.core.scope_guard import ScopeConfig, ScopeGuard
    from app.discovery.engine import DiscoveryConfig, DiscoveryEngine
    from app.discovery.schedule import new_run
    from app.models import Base, DiscoveryBatch

    workers = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    target = sys.argv[2] if len(sys.argv) > 2 else "10.200.0.0/18"
    db = Path(tempfile.mkdtemp()) / "perf.sqlite"
    engine = create_engine(f"sqlite:///{db}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    guard = ScopeGuard(
        ScopeConfig.from_dict(
            {"allow": {"cidrs": [target]}, "rate_limits": {"default_per_minute": 100000}}
        ),
        audit=DbAuditSink(factory),
    )
    config = DiscoveryConfig.from_file(ROOT / "rules" / "discovery.yaml")
    with factory() as session:
        run = new_run(
            session,
            config,
            [target],
            name="perf",
            settings={"workers": workers},
            actor="perf",
        )
        session.commit()
        run_id = run.id
    started = time.monotonic()
    with factory() as session:
        run = DiscoveryEngine(session, guard, config).run(run_id)
        batches = list(session.query(DiscoveryBatch).filter(DiscoveryBatch.run_id == run_id))
        sweep = [b for b in batches if b.phase == "sweep"]
        services = [b for b in batches if b.phase == "services"]
        sizes = sorted({b.addresses for b in sweep})
        result = {
            "target": target,
            "addresses": run.addresses_total,
            "hosts_up": run.hosts_up,
            "status": run.status,
            "workers": workers,
            "max_rate_per_worker": run.settings.get("max_rate"),
            "wall_seconds": round(time.monotonic() - started, 1),
            "sweep_batches": len(sweep),
            "batch_sizes": sizes,
            "sweep_seconds_sum": round(sum(b.duration_ms for b in sweep) / 1000, 1),
            "services_hosts": len(services),
            "services_seconds_avg": round(
                sum(b.duration_ms for b in services) / max(1, len(services)) / 1000, 1
            ),
            "addresses_per_second": run.summary.get("addresses_per_second"),
            "services_found": run.summary.get("services"),
            "web": run.summary.get("web"),
            "flags": run.summary.get("flags"),
            "max_rss_mib": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
        }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
