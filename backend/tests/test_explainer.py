"""AI Explainer: kontekst z bazy, walidator, cache „generuj raz”, szablon i audit."""

from __future__ import annotations

from dataclasses import replace

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.explainer.context import build_context
from app.explainer.fallback import render_fallback
from app.explainer.prompts import FACTS_PLACEHOLDER, load_template
from app.explainer.providers import FakeProvider, ProviderError
from app.explainer.service import ExplainerService, Listener, asset_header
from app.explainer.validator import count_sentences, validate
from app.models import Asset, AuditLog, Finding, LLMCache
from app.models.ops import AUDIENCES
from tests.explainer_helpers import CONFIG, CVE, GOOD, TITLES, seed_findings, vulnerability


@pytest.fixture
def seeded(session: Session) -> Session:
    seed_findings(session)
    return session


def service(session: Session, provider: FakeProvider | None) -> ExplainerService:
    return ExplainerService(session, CONFIG, provider=provider, titles=TITLES)


def audit_actions(session: Session) -> list[str]:
    return list(
        session.scalars(
            select(AuditLog.action)
            .where(AuditLog.action.like("explanation_%"))
            .order_by(AuditLog.id)
        )
    )


# --- kontekst i prompty ---


def test_context_is_built_from_database_fields_only(seeded: Session) -> None:
    context = build_context(vulnerability(seeded), CONFIG, TITLES)
    facts = context.facts_text()
    assert "CVE-2021-41773" in facts
    assert "Apache HTTP Server" in facts
    assert "wersja 2.4.49" in facts
    assert "7.5 na 10 (wysoka)" in facts
    assert "CISA KEV" in facts
    assert "2021-11-17" in facts
    assert "`httpd -v`" in facts
    assert context.allowed_versions() >= {"2.4.49", "7.5"}


def test_prompt_never_contains_asset_data(seeded: Session) -> None:
    """Tekst o CVE jest wspólny dla wszystkich zasobów, więc model nie widzi inwentarza."""
    provider = FakeProvider([GOOD[a] for a in AUDIENCES])
    explainer = service(seeded, provider)
    for audience in AUDIENCES:
        explainer.generate(vulnerability(seeded), audience, actor="test")
    sent = "\n".join(p.system + p.user for p in provider.prompts)
    for asset in seeded.scalars(select(Asset)):
        for secret in (asset.name, asset.owner, (asset.attributes or {}).get("address")):
            if secret:
                assert secret not in sent


def test_fix_version_comes_from_feed_ranges(seeded: Session) -> None:
    context = build_context(vulnerability(seeded, "CVE-2021-23017"), CONFIG, TITLES)
    (product,) = context.products
    assert product.fixed_version == "1.20.1"
    assert "1.20.1 lub nowsza" in context.facts_text()
    assert product.commands == ("nginx -v",)


@pytest.mark.parametrize("audience", AUDIENCES)
def test_prompts_are_versioned_files(audience: str) -> None:
    template = load_template(f"explain_{audience}")
    assert template.version == f"explain_{audience}.v2"
    assert FACTS_PLACEHOLDER in template.user
    assert "po polsku" in template.system
    assert template.render("- fakt").user.count("- fakt") == 1


# --- walidator ---


def check(seeded: Session, audience: str, text: str, known: set[str] | None = None) -> list[str]:
    context = build_context(vulnerability(seeded), CONFIG, TITLES)
    result = validate(
        text, limits=CONFIG.audiences[audience], context=context, known_cves=known or {CVE}
    )
    return result.codes


@pytest.mark.parametrize("audience", AUDIENCES)
def test_validator_accepts_grounded_polish_answer(seeded: Session, audience: str) -> None:
    assert check(seeded, audience, GOOD[audience]) == []


@pytest.mark.parametrize("audience", AUDIENCES)
@pytest.mark.parametrize(
    "cve_id", ["CVE-2021-41773", "CVE-2021-23017", "CVE-2022-24735", "CVE-2019-0211"]
)
def test_template_explanation_always_passes_the_validator(
    seeded: Session, audience: str, cve_id: str
) -> None:
    context = build_context(vulnerability(seeded, cve_id), CONFIG, TITLES)
    text = render_fallback(context, audience)
    result = validate(text, limits=CONFIG.audiences[audience], context=context, known_cves={cve_id})
    assert result.messages == []


def test_validator_rejects_cve_that_does_not_exist(seeded: Session) -> None:
    text = GOOD["operational"].replace("CVE-2021-41773", "CVE-2099-99999")
    assert "unknown_cve" in check(seeded, "operational", text, known=set())


def test_validator_rejects_real_cve_that_is_not_in_the_context(seeded: Session) -> None:
    text = GOOD["operational"] + " Podobna jest podatność CVE-2021-42013."
    codes = check(seeded, "operational", text, known={CVE, "CVE-2021-42013"})
    assert codes == ["unknown_cve"]


@pytest.mark.parametrize(
    ("addition", "code"),
    [
        (" Zaktualizuj do wersji 2.4.62.", "unknown_version"),
        (" Zaktualizuj do wersji v9.1.", "unknown_version"),
        (" Wykonaj `curl http://cel/cgi-bin/.%2e/etc/passwd`.", "unknown_command"),
        (" Zobacz https://example.org/poradnik.", "url"),
        (" Termin minął 2024-01-01.", "unknown_date"),
    ],
)
def test_validator_rejects_facts_outside_the_context(
    seeded: Session, addition: str, code: str
) -> None:
    context = build_context(vulnerability(seeded), CONFIG, TITLES)
    result = validate(
        GOOD["operational"] + addition,
        limits=CONFIG.audiences["operational"],
        context=context,
        known_cves={CVE},
    )
    assert code in result.codes
    assert not result.retryable


def test_validator_allows_names_copied_verbatim_from_facts(seeded: Session) -> None:
    text = GOOD["operational"] + " Problem dotyczy `file disclosure` w serwerze."
    assert check(seeded, "operational", text) == []
    typo = GOOD["operational"] + " Wersję pokaże `httpd --verssion`."
    assert check(seeded, "operational", typo) == ["unknown_command"]


def test_validator_allows_version_prefix_and_known_command(seeded: Session) -> None:
    text = GOOD["operational"] + " Gałąź 2.4 sprawdzisz poleceniem `httpd -v`."
    assert check(seeded, "operational", text) == []


@pytest.mark.parametrize(
    ("audience", "text", "code"),
    [
        ("executive", GOOD["operational"], "sentences"),
        ("executive", "Jest źle.", "length"),
        (
            "operational",
            "The vulnerability allows an attacker to read files and this is very bad for the "
            "server. The team should update it with the latest version from the vendor. It is "
            "urgent and has to be done.",
            "language",
        ),
        ("operational", GOOD["operational"] + " 请立即更新。", "language"),
        ("technical", GOOD["technical"].replace("Jak sprawdzić:", "Weryfikacja:"), "format"),
        ("technical", "", "empty"),
    ],
)
def test_form_problems_are_retryable(seeded: Session, audience: str, text: str, code: str) -> None:
    context = build_context(vulnerability(seeded), CONFIG, TITLES)
    result = validate(text, limits=CONFIG.audiences[audience], context=context, known_cves={CVE})
    assert code in result.codes
    assert result.retryable


def test_sentence_counter_ignores_versions_and_abbreviations() -> None:
    assert count_sentences("Dotyczy wersji 2.4.49, np. na serwerach WWW. Zaktualizuj ją.") == 2
    assert count_sentences("Jedno zdanie bez kropki") == 1


# --- usługa: generuj raz ---


def test_second_request_for_the_same_cve_does_not_call_the_model(seeded: Session) -> None:
    provider = FakeProvider([GOOD["operational"]])
    explainer = service(seeded, provider)
    first = explainer.generate(vulnerability(seeded), "operational", actor="user:anna")
    second = explainer.generate(vulnerability(seeded), "operational", actor="user:jan")
    assert (first.source, first.validation, first.cached) == ("model", "passed", False)
    assert (second.source, second.cached, second.text) == ("model", True, first.text)
    assert len(provider.prompts) == 1
    assert seeded.scalar(select(func.count()).select_from(LLMCache)) == 1
    assert audit_actions(seeded) == ["explanation_generated"]


def test_reading_never_calls_the_model(seeded: Session) -> None:
    provider = FakeProvider([GOOD["executive"]])
    shown = service(seeded, provider).get(vulnerability(seeded), "executive")
    assert (shown.source, shown.validation, shown.cached) == ("template", "none", False)
    assert "wersja automatyczna" in shown.label.lower()
    assert provider.prompts == []
    assert audit_actions(seeded) == []


def test_answer_with_unknown_cve_is_rejected_and_replaced_by_template(seeded: Session) -> None:
    bad = GOOD["operational"] + " Zobacz też CVE-2099-12345."
    provider = FakeProvider([bad])
    explainer = service(seeded, provider)
    result = explainer.generate(vulnerability(seeded), "operational", actor="user:anna")
    assert (result.source, result.validation) == ("template", "rejected")
    assert "CVE-2099-12345" not in result.text
    assert result.text == render_fallback(explainer.context(vulnerability(seeded)), "operational")
    assert len(provider.prompts) == 1  # błąd faktów: bez ponownej próby
    # odrzucenie też jest zapamiętane, więc kolejne wyświetlenie nie pyta modelu ponownie
    again = explainer.generate(vulnerability(seeded), "operational", actor="user:anna")
    assert (again.cached, again.validation) == (True, "rejected")
    assert len(provider.prompts) == 1
    entry = seeded.scalar(select(AuditLog).where(AuditLog.action == "explanation_rejected"))
    assert entry is not None
    assert entry.inputs["problems"] == ["unknown_cve"]
    assert "CVE-2099-12345" in entry.reason


def test_form_problem_gets_exactly_one_retry(seeded: Session) -> None:
    provider = FakeProvider(["Too short.", GOOD["technical"]])
    retries: list[int] = []
    tokens: list[str] = []
    result = service(seeded, provider).generate(
        vulnerability(seeded),
        "technical",
        actor="test",
        listener=Listener(on_token=tokens.append, on_retry=lambda: retries.append(1)),
    )
    assert (result.source, result.validation) == ("model", "passed")
    assert len(provider.prompts) == 2
    assert retries == [1]
    assert "".join(tokens).endswith(GOOD["technical"])

    stubborn = FakeProvider(["Too short.", "Still too short."])
    rejected = service(seeded, stubborn).generate(vulnerability(seeded), "executive", actor="test")
    assert (rejected.source, rejected.validation) == ("template", "rejected")
    assert len(stubborn.prompts) == 2


def test_model_failure_gives_template_and_is_not_cached(seeded: Session) -> None:
    provider = FakeProvider([ProviderError("Ollama: błąd połączenia"), GOOD["executive"]])
    explainer = service(seeded, provider)
    failed = explainer.generate(vulnerability(seeded), "executive", actor="test")
    assert (failed.source, failed.validation) == ("template", "unavailable")
    assert seeded.scalar(select(func.count()).select_from(LLMCache)) == 0
    # gdy model wróci, kolejne żądanie generuje normalnie
    recovered = explainer.generate(vulnerability(seeded), "executive", actor="test")
    assert (recovered.source, recovered.validation) == ("model", "passed")
    assert audit_actions(seeded) == ["explanation_unavailable", "explanation_generated"]


def test_system_works_without_any_model(seeded: Session) -> None:
    explainer = service(seeded, None)
    for audience in AUDIENCES:
        result = explainer.generate(vulnerability(seeded), audience, actor="test")
        assert (result.source, result.validation) == ("template", "unavailable")
        assert CVE in result.text
    assert seeded.scalar(select(func.count()).select_from(LLMCache)) == 0


def test_regenerate_replaces_the_cached_text(seeded: Session) -> None:
    newer = GOOD["executive"].replace("pilnie", "niezwłocznie")
    provider = FakeProvider([GOOD["executive"], newer])
    explainer = service(seeded, provider)
    explainer.generate(vulnerability(seeded), "executive", actor="test")
    again = explainer.generate(vulnerability(seeded), "executive", actor="test", regenerate=True)
    assert again.text == newer
    assert seeded.scalar(select(func.count()).select_from(LLMCache)) == 1


def test_cache_key_depends_on_prompt_version(
    seeded: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.explainer.service as module

    provider = FakeProvider([GOOD["executive"], GOOD["executive"]])
    explainer = service(seeded, provider)
    explainer.generate(vulnerability(seeded), "executive", actor="test")
    original = load_template
    monkeypatch.setattr(
        module,
        "load_template",
        lambda name: replace(original(name), version=f"{name}.v99"),
    )
    explainer.generate(vulnerability(seeded), "executive", actor="test")
    assert len(provider.prompts) == 2
    assert seeded.scalar(select(func.count()).select_from(LLMCache)) == 2


def test_audit_entry_says_what_why_and_on_what_data(seeded: Session) -> None:
    explainer = service(seeded, FakeProvider([GOOD["operational"]]))
    explainer.generate(vulnerability(seeded), "operational", actor="user:anna")
    entry = seeded.scalar(select(AuditLog).where(AuditLog.action == "explanation_generated"))
    assert entry is not None
    assert (entry.actor, entry.object_type, entry.object_id) == ("user:anna", "vulnerability", CVE)
    context = explainer.context(vulnerability(seeded))
    assert entry.inputs["context_sha256"] == context.digest
    assert entry.inputs["prompt_version"] == "explain_operational.v2"
    assert entry.inputs["model"] == "fake-model"
    assert entry.inputs["external"] is False


def test_asset_context_is_added_by_code(seeded: Session) -> None:
    finding = seeded.scalars(
        select(Finding).join(Asset, Asset.id == Finding.asset_id).where(Asset.name == "web-01")
    ).first()
    assert finding is not None
    header = asset_header(seeded, finding)
    assert header.startswith("Dotyczy: web-01 (")
    assert "2.4.49" in header
    assert "dostępny z internetu" in header
    assert "krytyczność 5/5" in header
    assert "właściciel: Zespół WWW" in header
