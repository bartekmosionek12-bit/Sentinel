"""Zadania Celery. W Etapie 1 tylko kontrola, że każda kolejka ma działającego workera."""

from __future__ import annotations

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
