"""Test skali discovery: pełny przebieg silnika na zakresie > 10 000 adresów.

Uruchamiany w przestrzeni nazw z `scripts/perf_lab.sh` (syntetyczne laboratorium), z bazą
SQLite w pliku tymczasowym, prawdziwym nmapem i prawdziwym fingerprintingiem HTTP. Wypisuje
czas całości i faz, CPU (proces + nmap), szczytowe RAM i statystyki partii jako JSON.
  sudo ip netns exec asi-lab backend/.venv/bin/python scripts/perf_discovery.py 10.200.0.0/18
"""

from __future__ import annotations

import json
import resource
import sys
import tempfile
import time
import uuid
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.core.audit import DbAuditSink  # noqa: E402
from app.core.scope_guard import ScopeConfig, ScopeGuard  # noqa: E402
from app.discovery.engine import DiscoveryConfig, DiscoveryEngine, parse_targets  # noqa: E402
from app.models import Base, DiscoveryBatch, DiscoveryRun, Observation  # noqa: E402


def main(target: str, overrides: dict[str, object]) -> None:
    db = Path(tempfile.mkdtemp()) / "perf.db"
    engine = create_engine(f"sqlite+pysqlite:///{db}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    guard = ScopeGuard(
        ScopeConfig.from_dict(
            {"allow": {"cidrs": [target]}, "rate_limits": {"default_per_minute": 100000}}
        ),
        audit=DbAuditSink(factory),
    )
    config = DiscoveryConfig.from_file(ROOT / "rules" / "discovery.yaml")
    settings = config.settings(overrides)
    parsed = parse_targets([target])
    with factory() as session:
        run = DiscoveryRun(
            name="perf",
            status="queued",
            source="scan",
            targets=[target],
            settings=settings.as_dict() if hasattr(settings, "as_dict") else dict(overrides),
            created_by="perf",
            addresses_total=parsed.addresses,
        )
        session.add(run)
        session.commit()
        run_id = run.id
    started = time.monotonic()
    with factory() as session:
        done = DiscoveryEngine(session, guard, config).run(uuid.UUID(str(run_id)))
    wall = time.monotonic() - started
    me = resource.getrusage(resource.RUSAGE_SELF)
    kids = resource.getrusage(resource.RUSAGE_CHILDREN)
    with factory() as session:
        batches = list(session.scalars(select(DiscoveryBatch).where(DiscoveryBatch.run_id == run_id)))
        hosts = list(session.scalars(select(Observation).where(Observation.run_id == run_id)))
        sweep = [b for b in batches if b.phase == "sweep"]
        services = [b for b in batches if b.phase == "services"]
        report = {
            "target": target,
            "addresses": parsed.addresses,
            "status": done.status,
            "settings": done.settings,
            "wall_seconds": round(wall, 1),
            "sweep_seconds": round(sum(b.duration_ms for b in sweep) / 1000 / max(1, settings.workers), 1),
            "hosts_up": len(hosts),
            "open_services": sum(len(h.services) for h in hosts),
            "http_fingerprints": sum(len(h.http) for h in hosts),
            "flags": sum(len(h.flags) for h in hosts),
            "sweep_batches": len(sweep),
            "batch_sizes": sorted({b.addresses for b in sweep}),
            "avg_sweep_batch_s": round(mean(b.duration_ms for b in sweep) / 1000, 1) if sweep else 0,
            "service_tasks": len(services),
            "avg_service_task_s": round(mean(b.duration_ms for b in services) / 1000, 1)
            if services
            else 0,
            "cpu_seconds_python": round(me.ru_utime + me.ru_stime, 1),
            "cpu_seconds_nmap": round(kids.ru_utime + kids.ru_stime, 1),
            "peak_rss_mb_python": round(me.ru_maxrss / 1024, 1),
            "peak_rss_mb_nmap_max": round(kids.ru_maxrss / 1024, 1),
            "addresses_per_second": round(parsed.addresses / wall, 1),
        }
    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    extra = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    main(sys.argv[1], extra)
