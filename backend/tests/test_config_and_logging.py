from __future__ import annotations

import json
import logging

import pytest

from app.core.config import Settings
from app.core.logging import JsonFormatter
from app.workers.celery_app import QUEUES, celery_app


def test_demo_mode_is_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("DEMO_MODE", "DEMO_APPROVAL_EXPIRES_AT"):
        monkeypatch.delenv(name, raising=False)
    settings = Settings(_env_file=None)
    assert settings.demo_mode is False
    assert settings.demo_approval_expires_at is None


def test_empty_expiry_means_no_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEMO_APPROVAL_EXPIRES_AT", "")
    assert Settings(_env_file=None).demo_approval_expires_at is None


def test_demo_lab_cidr_must_be_a_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEMO_LAB_CIDR", "172.30.99.1/24")
    with pytest.raises(ValueError, match="host bits"):
        _ = Settings(_env_file=None).demo_lab_network


def test_json_log_line() -> None:
    record = logging.LogRecord(
        "sentinel.test", logging.INFO, __file__, 1, "zażółć %s", ("x",), None
    )
    record.asset_id = "abc"
    line = json.loads(JsonFormatter().format(record))
    assert line["msg"] == "zażółć x"
    assert line["level"] == "INFO"
    assert line["asset_id"] == "abc"


def test_celery_queues_and_routes() -> None:
    assert set(QUEUES) == {"default", "scans", "feeds", "llm", "agent", "agent_tests"}
    routes = celery_app.conf.task_routes
    assert routes["app.workers.tasks.llm.*"] == {"queue": "llm"}
    assert routes["app.workers.tasks.scans.*"] == {"queue": "scans"}
    # Test agenta ma własną kolejkę i worker; agent nie dzieli z nim kolejki (moduł 19).
    assert routes["app.workers.tasks.agent_tests.*"] == {"queue": "agent_tests"}
    assert routes["app.workers.tasks.agent.*"] == {"queue": "agent"}
    assert celery_app.conf.task_default_queue == "default"
