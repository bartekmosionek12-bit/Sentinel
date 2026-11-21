"""Provider promptfoo dla Sentka: pytanie przez prawdziwą ścieżkę `app.assistant.service.ask`.

`config.backend`:
- `hostile`: wrogi model (atrapa), który zwraca dokładnie JSON z `vars.model_json`, czyli
  najgorszą klasyfikację, jaką mógłby wymyślić model przejęty przez treść pytania;
- `ollama`: prawdziwy model lokalny (`LLM_MODEL`, `OLLAMA_URL`).
Wynik to JSON odpowiedzi (intencja, tekst, akcja, linki), który sprawdzają asercje
deterministyczne w `assistant_assertions.js`.
"""

from __future__ import annotations

import logging
import os
from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.assistant.classify import ModelClassifier
from app.assistant.service import ask
from app.explainer.providers import FakeProvider, LLMProvider, OllamaProvider
from app.iam.deps import get_role_catalog
from app.iam.tokens import Principal
from app.models import Base
from app.org.shadow import evaluate_shadow
from app.org.sources import collect, demo_sources
from app.org.sync import sync_organization
from app.pipeline import Rulebook, analyze
from app.reports.config import ReportsConfig
from tests.pipeline_helpers import RULES, seed_feeds, seed_inventory

ROOT = Path(__file__).resolve().parents[1]
TODAY = date(2026, 11, 21)


@lru_cache
def world() -> Session:
    logging.disable(logging.CRITICAL)
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    rulebook = Rulebook.from_dir(RULES)
    seed_feeds(session)
    seed_inventory(session)
    snapshot = collect(demo_sources(ROOT / "demo-lab" / "org"))
    sync_organization(session, snapshot, actor="ai-tests")
    analyze(session, rulebook)
    evaluate_shadow(session, rulebook.scoring)
    session.commit()
    return session


def manager() -> Principal:
    roles = frozenset({"manager"})
    return Principal(
        subject="ai-tests",
        username="ai-tests",
        display_name="ai-tests",
        email="",
        kind="human",
        roles=roles,
        permissions=get_role_catalog().resolve(roles, mfa=False),
        mfa=False,
        client_id="ai-tests",
        session_id=None,
    )


def model(backend: str, vars_: dict[str, Any]) -> LLMProvider:
    if backend == "ollama":
        return OllamaProvider(
            base_url=os.environ.get("OLLAMA_URL", "http://localhost:11434"),
            model=os.environ.get("LLM_MODEL", "qwen3-4b-q4km"),
            num_ctx=2048,
            timeout=30.0,
        )
    return FakeProvider([str(vars_.get("model_json") or '{"intent": "out_of_scope"}')])


def call_api(prompt: str, options: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    backend = str((options.get("config") or {}).get("backend", "hostile"))
    vars_ = context.get("vars") or {}
    timeout = 30.0 if backend == "ollama" else 4.0
    try:
        session = world()
        answer = ask(
            session,
            str(vars_.get("question") or prompt),
            principal=manager(),
            config=ReportsConfig.from_dir(RULES),
            classifier=ModelClassifier(model(backend, vars_), timeout_seconds=timeout),
            today=TODAY,
            pseudonyms=True,
        )
        session.rollback()
        return {
            "output": {
                "intent": answer.intent,
                "source": answer.source,
                "text": answer.text,
                "action": answer.action,
                "links": answer.links,
            }
        }
    except Exception as error:  # promptfoo pokazuje błąd przy przypadku
        return {"error": f"{type(error).__name__}: {error}"}
