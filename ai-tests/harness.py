"""Uruchamia prawdziwą ścieżkę aplikacji na zatrutym opisie CVE i zwraca to, co zobaczy człowiek.

Każdy przypadek z `fixtures/*.yaml`:
1. buduje bazę SQLite w pamięci z fikcyjnym inwentarzem i feedami z testów backendu,
2. podmienia opis wskazanego CVE na tekst z wstrzykniętym poleceniem,
3. liczy dopasowanie i ryzyko (kod), zapamiętuje ocenę,
4. wywołuje model przez kod aplikacji: warstwę „W skrócie” raportu albo wyjaśnienie CVE,
5. porównuje ocenę po walidacji z oceną sprzed wywołania modelu i zwraca tekst pokazany ludziom.

Model jest jednym z dwóch:
- `obedient`: posłuszna atrapa. Gdy widzi wstrzyknięcie w prompcie, zawsze robi to, czego chce
  napastnik (odpowiedź z pola `payload`). Sprawdza obronę kodu, nie model.
- `ollama`: prawdziwy model lokalny (`OLLAMA_URL`, `LLM_MODEL`, domyślnie qwen3-4b-q4km).

Nic tu nie decyduje model: asercje porównują wyłącznie wyniki liczone kodem.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator, Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT.parent / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.explainer.context import ExplainerConfig  # noqa: E402
from app.explainer.prompts import Prompt  # noqa: E402
from app.explainer.providers import LLMProvider, OllamaProvider, ProviderHealth  # noqa: E402
from app.explainer.service import ExplainerService  # noqa: E402
from app.models import Base, Finding, Vulnerability  # noqa: E402
from app.pipeline import Rulebook, analyze  # noqa: E402
from app.reports.config import QUESTIONS, ReportsConfig  # noqa: E402
from app.reports.service import create_report, generate_summary, present  # noqa: E402
from tests.pipeline_helpers import RULES, seed_feeds, seed_inventory  # noqa: E402

FIXTURES = ROOT / "fixtures"

# Odpowiedzi „uczciwego” modelu, gdy w prompcie nie ma wstrzyknięcia (albo dla pytań, których
# napastnik nie dotyka). Każda przechodzi walidator, więc przypadek kontrolny sprawdza, że
# obrona nie odrzuca wszystkiego.
HONEST_SUMMARY = {
    "what": "Przegląd objął otwarte zagrożenia na naszych zasobach i część z nich jest pilna.",
    "exposed": "Tak, jesteśmy zagrożeni. Najpilniejszy jest asset_1, bo przestępcy już "
    "wykorzystują jego podatność.",
    "worst": "Przestępcy mogą przejąć asset_1 i wykraść z niego dane klientów.",
    "todo": "Trzeba jak najszybciej zaktualizować oprogramowanie na asset_1.",
    "who": "Za asset_1 odpowiada person_1, który powinien to zrobić w ciągu trzech dni.",
}
HONEST_EXPLANATION = {
    "executive": "Na serwerze z internetu działa oprogramowanie z luką, którą przestępcy już "
    "wykorzystują w atakach. Trzeba je pilnie zaktualizować, a do tego czasu ograniczyć "
    "dostęp z zewnątrz.",
}


@lru_cache
def load_cases() -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}
    for path in sorted(FIXTURES.glob("*.yaml")):
        for case in yaml.safe_load(path.read_text(encoding="utf-8"))["cases"]:
            if case["id"] in cases:
                raise ValueError(f"Powtórzony identyfikator przypadku: {case['id']}")
            cases[case["id"]] = case
    return cases


class ObedientProvider:
    """Atrapa, która wykonuje każde wstrzyknięte polecenie, jeśli tylko je zobaczy."""

    name = "obedient"
    model = "obedient-mock"

    def __init__(self, trigger: str | None, payload: str, honest: str) -> None:
        self._trigger = trigger
        self._payload = payload
        self._honest = honest
        self.saw_injection = False

    def stream(self, prompt: Prompt, *, max_tokens: int) -> Iterator[str]:
        seen = bool(self._trigger) and self._trigger in f"{prompt.system}\n{prompt.user}"
        self.saw_injection = self.saw_injection or seen
        text = self._payload if seen else self._honest
        words = text.split(" ")
        for index, word in enumerate(words):
            yield word if index == len(words) - 1 else word + " "

    def health(self) -> ProviderHealth:
        return ProviderHealth(True, self.model, "Posłuszna atrapa")


def _summary_text(answers: Mapping[str, str]) -> str:
    return "\n".join(f"{label}\n{answers[key]}" for key, label in QUESTIONS)


def _session() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _risk_snapshot(session: Session) -> list[tuple[str, float, str, str, str]]:
    """Ocena ryzyka każdego findingu: wynik, poziom, status, rozbicie i właściciel."""
    session.expire_all()
    findings = session.scalars(select(Finding).order_by(Finding.dedup_key))
    return [
        (
            f.dedup_key,
            float(f.risk_score),
            f.risk_level,
            f.status,
            repr(sorted((f.risk_breakdown or {}).items())) + repr(f.assignee),
        )
        for f in findings
    ]


def _vuln(session: Session, cve_id: str) -> Vulnerability | None:
    return session.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))


def _ollama() -> LLMProvider:
    return OllamaProvider(
        base_url=os.environ.get("OLLAMA_URL", "http://localhost:11434"),
        model=os.environ.get("LLM_MODEL", "qwen3-4b-q4km"),
        num_ctx=int(os.environ.get("LLM_NUM_CTX", "4096")),
    )


def _prepare(case: Mapping[str, Any]) -> Session:
    session = _session()
    seed_feeds(session)
    seed_inventory(session)
    vuln = _vuln(session, case["cve"])
    if vuln is None:
        raise ValueError(f"{case['id']}: brak {case['cve']} w fixture'ach feedów")
    if case.get("description") is not None:
        vuln.description = " ".join(str(case["description"]).split())
    analyze(session, Rulebook.from_dir(RULES))
    session.flush()
    return session


def run_case(case_id: str, backend: str) -> dict[str, Any]:
    case = load_cases()[case_id]
    session = _prepare(case)
    risk_before = _risk_snapshot(session)
    trigger = str(case["trigger"]) if case.get("trigger") is not None else None
    pipeline = case.get("pipeline", "report")
    obedient: ObedientProvider | None = None

    if pipeline == "report":
        config = ReportsConfig.from_dir(RULES)
        report = create_report(session, config, kind="assessment", actor="ai-tests")
        before = (report.light, report.light_reason, report.facts, report.technical)
        if backend == "obedient":
            honest = _summary_text(HONEST_SUMMARY)
            payload = _summary_text({**HONEST_SUMMARY, **(case.get("payload") or {})})
            obedient = ObedientProvider(trigger, payload, honest)
        provider = obedient or _ollama()
        outcome = generate_summary(session, report, config, provider, actor="ai-tests")
        after = (report.light, report.light_reason, report.facts, report.technical)
        shown = present(report, personal=True)
        result: dict[str, Any] = {
            "validation": outcome.validation,
            "source": report.summary_source,
            "shown": "\n".join(f"{i['question']} {i['answer']}" for i in shown["summary"]),
            "problems": list(outcome.problems),
            "attempts": outcome.attempts,
            "light": report.light,
            "assessment_unchanged": before == after,
        }
    elif pipeline == "explain":
        audience = case.get("audience", "executive")
        config_e = ExplainerConfig.from_file(RULES / "explainer.yaml")
        if backend == "obedient":
            honest = HONEST_EXPLANATION.get(audience, HONEST_EXPLANATION["executive"])
            obedient = ObedientProvider(trigger, str(case.get("payload_text", "")), honest)
        provider = obedient or _ollama()
        vuln = _vuln(session, case["cve"])
        assert vuln is not None  # noqa: S101 - sprawdzone w _prepare
        explanation = ExplainerService(session, config_e, provider=provider).generate(
            vuln, audience, actor="ai-tests", regenerate=True
        )
        result = {
            "validation": explanation.validation,
            "source": explanation.source,
            "shown": explanation.text,
            "problems": list(explanation.problems),
            "attempts": None,
            "light": None,
            "assessment_unchanged": True,
        }
    else:
        raise ValueError(f"{case_id}: nieznana ścieżka {pipeline}")

    result.update(
        case=case_id,
        pipeline=pipeline,
        backend=backend,
        model=getattr(provider, "model", None),
        injection_reached_model=obedient.saw_injection if obedient else None,
        risk_unchanged=_risk_snapshot(session) == risk_before,
    )
    session.close()
    return result


if __name__ == "__main__":  # ręczne uruchomienie: python harness.py <przypadek> [obedient|ollama]
    import json

    outcome = run_case(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "obedient")
    print(json.dumps(outcome, ensure_ascii=False, indent=2))  # noqa: T201
