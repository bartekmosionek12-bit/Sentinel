"""Zadania Celery. Każde zadanie otwiera własną sesję i samo ją zatwierdza."""

from __future__ import annotations

import uuid
from typing import Any

from app.core.config import get_settings
from app.core.db import get_sessionmaker
from app.feeds.service import sync_all
from app.pipeline import analyze
from app.runtime import channel_sender, feed_source, get_rulebook, scan_service
from app.workers.celery_app import celery_app


@celery_app.task(name="app.workers.tasks.ping")
def ping() -> str:
    return "pong:default"


@celery_app.task(name="app.workers.tasks.scans.ping")
def ping_scans() -> str:
    return "pong:scans"


@celery_app.task(name="app.workers.tasks.feeds.ping")
def ping_feeds() -> str:
    return "pong:feeds"


@celery_app.task(name="app.workers.tasks.llm.ping")
def ping_llm() -> str:
    return "pong:llm"


@celery_app.task(name="app.workers.tasks.scans.run_scan")
def run_scan(trigger: str = "scheduled", actor: str = "system") -> dict[str, Any]:
    with get_sessionmaker()() as session:
        run = scan_service(session).run(trigger=trigger, actor=actor)
        return {"scan_run_id": str(run.id), "status": run.status, "summary": run.summary}


@celery_app.task(name="app.workers.tasks.scans.approve_action")
def approve_action(action_id: str, approved_by: str, reason: str) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        action = scan_service(session).approve(
            uuid.UUID(action_id), approved_by=approved_by, reason=reason
        )
        return {"action_id": str(action.id), "status": action.status, "detail": action.detail}


@celery_app.task(name="app.workers.tasks.feeds.sync_feeds")
def sync_feeds(actor: str = "system") -> dict[str, Any]:
    """Synchronizuje feedy i zleca ponowną analizę (kolejka `default`)."""
    with get_sessionmaker()() as session:
        summary = sync_all(session, feed_source(session, get_settings()), actor=actor)
        session.commit()
    run_analysis.delay()
    return {"feeds": summary.results, "changed_cves": len(summary.changed_cves)}


@celery_app.task(name="app.workers.tasks.run_analysis")
def run_analysis() -> dict[str, int]:
    with get_sessionmaker()() as session:
        report = analyze(session, get_rulebook(), channel_sender())
        session.commit()
        return report.summary()
