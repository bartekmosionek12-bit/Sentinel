"""API wyjaśnień: cache, zlecenie generowania, strumień SSE i praca bez modelu."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.api.deps import get_dispatcher
from app.api.explain import get_explainer_factory, llm_health
from app.core.config import Settings, get_settings
from app.explainer.providers import FakeProvider, ProviderHealth
from app.explainer.service import ExplainerService, Listener
from app.explainer.stream import MemoryEventBus
from app.models import Asset, AuditLog, Finding, LLMCache, Vulnerability
from app.runtime import get_event_bus
from tests.explainer_helpers import CONFIG, CVE, GOOD, TITLES, seed_findings


class InlineLlmDispatcher:
    """Wykonuje zadanie kolejki `llm` od razu, tak jak worker, i publikuje zdarzenia."""

    def __init__(
        self, factory: sessionmaker[Session], provider: FakeProvider, bus: MemoryEventBus
    ) -> None:
        self._factory = factory
        self._provider = provider
        self._bus = bus
        self.calls: list[tuple[str, str, str, bool]] = []

    def generate_explanation(
        self,
        cve_id: str,
        audience: str,
        actor: str,
        job_id: str | None,
        *,
        regenerate: bool = False,
        use_external: bool = False,
        background: bool = False,
    ) -> str:
        assert job_id is not None
        self.calls.append((cve_id, audience, actor, use_external))
        with self._factory() as session:
            vuln = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
            assert vuln is not None
            self._bus.publish(job_id, {"type": "start"})
            result = ExplainerService(
                session, CONFIG, provider=self._provider, titles=TITLES
            ).generate(
                vuln,
                audience,
                actor=actor,
                regenerate=regenerate,
                listener=Listener(
                    on_token=lambda t: self._bus.publish(job_id, {"type": "token", "text": t}),
                    on_retry=lambda: self._bus.publish(job_id, {"type": "retry"}),
                ),
            )
            session.commit()
        self._bus.publish(
            job_id, {"type": "done", "source": result.source, "validation": result.validation}
        )
        return "task-1"


class Setup:
    def __init__(self, client: TestClient, factory: sessionmaker[Session]) -> None:
        self.client = client
        self.factory = factory
        self.bus = MemoryEventBus()
        self.provider = FakeProvider()
        self.dispatcher = InlineLlmDispatcher(factory, self.provider, self.bus)
        self.health = ProviderHealth(True, "fake-model", "Atrapa modelu")
        self.settings = Settings(_env_file=None, LLM_MODEL="fake-model")
        overrides: dict[Any, Any] = client.app.dependency_overrides  # type: ignore[attr-defined]
        overrides[get_dispatcher] = lambda: self.dispatcher
        overrides[get_event_bus] = lambda: self.bus
        overrides[llm_health] = lambda: self.health
        overrides[get_settings] = lambda: self.settings
        overrides[get_explainer_factory] = lambda: (
            lambda session: ExplainerService(session, CONFIG, provider=self.provider, titles=TITLES)
        )
        with factory() as session:
            seed_findings(session)
            session.commit()
            finding = session.scalars(
                select(Finding)
                .join(Asset, Asset.id == Finding.asset_id)
                .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
                .where(Asset.name == "web-01", Vulnerability.cve_id == CVE)
            ).one()
            self.url = f"/api/findings/{finding.id}/explanation"

    def events(self, job_id: str) -> list[dict[str, Any]]:
        response = self.client.get(f"/api/explanations/jobs/{job_id}/events")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        return [
            json.loads(line.removeprefix("data: "))
            for line in response.text.splitlines()
            if line.startswith("data: ")
        ]


@pytest.fixture
def env(client: TestClient, session_factory: sessionmaker[Session]) -> Setup:
    return Setup(client, session_factory)


def test_explanation_is_shown_from_template_until_generated(env: Setup) -> None:
    body = env.client.get(env.url, params={"audience": "executive"}).json()
    assert (body["source"], body["validation"], body["cached"]) == ("template", "none", False)
    assert body["label"].startswith("Wersja automatyczna")
    assert body["asset_context"].startswith("Dotyczy: web-01 (")
    assert CVE in body["text"]
    assert body["model"] is None
    assert env.provider.prompts == []


def test_generation_streams_tokens_and_second_view_uses_cache(env: Setup) -> None:
    env.provider._responses.append(GOOD["operational"])
    requested = env.client.post(env.url, json={"audience": "operational", "actor": "anna"})
    assert requested.status_code == 202
    job_id = requested.json()["job_id"]
    assert job_id

    events = env.events(job_id)
    kinds = [e["type"] for e in events]
    assert kinds[:2] == ["queued", "start"]
    assert kinds[-1] == "done"
    assert "".join(e["text"] for e in events if e["type"] == "token") == GOOD["operational"]
    assert events[-1]["validation"] == "passed"

    shown = env.client.get(env.url, params={"audience": "operational"}).json()
    assert (shown["source"], shown["cached"], shown["model"]) == ("model", True, "fake-model")
    assert shown["text"] == GOOD["operational"]
    assert "sprawdzone automatycznie" in shown["label"]

    # drugie żądanie: tekst z cache, bez zadania i bez modelu
    again = env.client.post(env.url, json={"audience": "operational", "actor": "jan"}).json()
    assert again["job_id"] is None
    assert again["explanation"]["text"] == GOOD["operational"]
    assert len(env.dispatcher.calls) == 1
    assert len(env.provider.prompts) == 1
    assert env.dispatcher.calls[0] == (CVE, "operational", "user:anna", False)


def test_rejected_answer_is_visible_as_template_with_reason(env: Setup) -> None:
    env.provider._responses.append(GOOD["executive"] + " Patrz CVE-2099-0001.")
    job_id = env.client.post(env.url, json={"audience": "executive"}).json()["job_id"]
    done = env.events(job_id)[-1]
    assert (done["type"], done["source"], done["validation"]) == ("done", "template", "rejected")
    shown = env.client.get(env.url, params={"audience": "executive"}).json()
    assert shown["source"] == "template"
    assert "nie przeszła kontroli" in shown["label"]
    assert "CVE-2099-0001" not in shown["text"]
    with env.factory() as session:
        assert session.scalar(select(LLMCache.validation)) == "rejected"
        assert session.scalar(select(AuditLog.id).where(AuditLog.action == "explanation_rejected"))


def test_without_model_request_returns_template_and_queues_nothing(env: Setup) -> None:
    env.health = ProviderHealth(False, "", "Model nie jest skonfigurowany (LLM_MODEL jest pusty)")
    response = env.client.post(env.url, json={"audience": "technical"})
    assert response.status_code == 202
    body = response.json()
    assert body["job_id"] is None
    assert "LLM_MODEL" in body["detail"]
    assert body["explanation"]["source"] == "template"
    assert "Co to jest:" in body["explanation"]["text"]
    assert env.dispatcher.calls == []
    status = env.client.get("/api/llm/status").json()
    assert (status["available"], status["external_enabled"]) == (False, False)


def test_external_model_is_refused_unless_admin_enabled_it(env: Setup) -> None:
    response = env.client.post(env.url, json={"audience": "executive", "provider": "external"})
    assert response.status_code == 403
    assert "wyłączony" in response.json()["detail"]
    assert env.dispatcher.calls == []

    env.settings = Settings(_env_file=None, LLM_MODEL="fake-model", EXTERNAL_LLM_ENABLED="true")
    env.provider._responses.append(GOOD["executive"])
    accepted = env.client.post(env.url, json={"audience": "executive", "provider": "external"})
    assert accepted.status_code == 202
    assert env.dispatcher.calls[0][3] is True


def test_unknown_finding_job_and_audience_are_rejected(env: Setup) -> None:
    missing = "/api/findings/00000000-0000-0000-0000-000000000000/explanation"
    assert env.client.get(missing).status_code == 404
    assert env.client.get(env.url, params={"audience": "poetycki"}).status_code == 422
    assert env.client.get("/api/explanations/jobs/nie-ma/events").status_code == 404


def test_llm_status_reports_model(env: Setup) -> None:
    status = env.client.get("/api/llm/status").json()
    assert status == {
        "enabled": True,
        "available": True,
        "model": "fake-model",
        "detail": "Atrapa modelu",
        "external_enabled": False,
    }
