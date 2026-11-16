"""Celery: osobne kolejki, żeby wolne zadania nie blokowały szybkich.

* `scans`   aktywne skanowanie (jedyny worker w sieci z dostępem do celów)
* `feeds`   pobieranie feedów threat intelligence
* `llm`     inferencja, zawsze concurrency=1
* `default` planner, matching, scoring, powiadomienia
"""

from __future__ import annotations

from celery import Celery
from celery.signals import setup_logging

from app.core.config import get_settings
from app.core.logging import configure_logging

QUEUES = ("default", "scans", "feeds", "llm")

settings = get_settings()

celery_app = Celery("sentinel", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(
    task_default_queue="default",
    task_routes={
        "app.workers.tasks.scans.*": {"queue": "scans"},
        "app.workers.tasks.feeds.*": {"queue": "feeds"},
        "app.workers.tasks.llm.*": {"queue": "llm"},
    },
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    result_expires=3600,
    broker_connection_retry_on_startup=True,
    imports=("app.workers.tasks",),
)


@setup_logging.connect
def _configure_logging(**_: object) -> None:
    configure_logging(settings.log_level)
