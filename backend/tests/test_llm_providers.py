"""Dostawcy modeli i anonimizator: inferencja lokalna, zewnętrzny model tylko po anonimizacji."""

from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.explainer.anonymizer import (
    AnonymizedPrompt,
    Anonymizer,
    InventoryEntry,
    inventory_entries,
)
from app.explainer.prompts import Prompt
from app.explainer.providers import (
    ExternalProvider,
    FakeProvider,
    OllamaProvider,
    ProviderError,
    generate,
    is_local_url,
)
from app.explainer.service import ExplainerService
from app.models import Asset, AuditLog
from app.runtime import external_provider, local_provider
from tests.explainer_helpers import CONFIG, GOOD, TITLES, seed_findings, vulnerability

PROMPT = Prompt("system", "użytkownik", "test.v1")


def ollama(handler: httpx.MockTransport, model: str = "model-a") -> OllamaProvider:
    return OllamaProvider(
        base_url="http://ollama:11434", model=model, client=httpx.Client(transport=handler)
    )


def ndjson(*events: dict[str, object]) -> bytes:
    return "\n".join(json.dumps(e) for e in events).encode()


# --- model lokalny ---


@pytest.mark.parametrize(
    ("url", "local"),
    [
        ("http://ollama:11434", True),
        ("http://localhost:11434", True),
        ("http://127.0.0.1:11434", True),
        ("http://10.0.5.7:11434", True),
        ("http://[::1]:11434", True),
        ("https://api.example.com", False),
        ("http://ollama.example.com:11434", False),
        ("http://8.8.8.8:11434", False),
        ("http://user:haslo@ollama:11434", False),
        ("ftp://ollama", False),
        ("", False),
    ],
)
def test_local_inference_accepts_only_local_addresses(url: str, local: bool) -> None:
    assert is_local_url(url) is local
    if not local:
        with pytest.raises(ProviderError, match="adres lokalny"):
            OllamaProvider(base_url=url, model="m")


def test_ollama_stream_sends_limits_and_collects_tokens() -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(
            200,
            content=ndjson(
                {"message": {"content": "<think>plan"}},
                {"message": {"content": " ukryty</think>Dzień "}},
                {"message": {"content": "dobry"}},
                {"message": {"content": ""}, "done": True, "eval_count": 2, "eval_duration": 10**9},
            ),
        )

    provider = ollama(httpx.MockTransport(handler))
    tokens: list[str] = []
    result = generate(provider, PROMPT, max_tokens=64, on_token=tokens.append)
    assert result.text == "Dzień dobry"
    assert "".join(tokens) == "Dzień dobry"
    assert (result.model, result.tokens) == ("model-a", 2)
    (body,) = seen
    assert body["model"] == "model-a"
    assert body["stream"] is True
    assert body["think"] is False
    assert body["messages"] == [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "użytkownik"},
    ]
    options = body["options"]
    assert isinstance(options, dict)
    assert options["num_predict"] == 64
    assert options["num_ctx"] == 4096
    assert options["num_thread"] >= 1


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500, content=b"blad"),
        httpx.Response(200, content=b"to nie json"),
        httpx.Response(200, content=ndjson({"error": "model not found"})),
    ],
)
def test_ollama_errors_become_provider_errors(response: httpx.Response) -> None:
    provider = ollama(httpx.MockTransport(lambda _request: response))
    with pytest.raises(ProviderError):
        generate(provider, PROMPT, max_tokens=8)


def test_ollama_connection_failure_is_a_provider_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("brak połączenia", request=request)

    provider = ollama(httpx.MockTransport(handler))
    with pytest.raises(ProviderError, match="błąd połączenia"):
        generate(provider, PROMPT, max_tokens=8)
    assert provider.health().available is False


def test_ollama_health_reports_missing_model() -> None:
    tags = httpx.Response(200, json={"models": [{"name": "model-a:latest"}]})
    transport = httpx.MockTransport(lambda _request: tags)
    assert ollama(transport, "model-a").health().available is True
    missing = ollama(transport, "model-b").health()
    assert missing.available is False
    assert "fetch_models" in missing.detail
    assert ollama(transport, "").health().available is False


def test_defaults_mean_no_model_and_no_external_provider() -> None:
    settings = Settings(_env_file=None)
    assert settings.llm_model == ""
    assert settings.external_llm_enabled is False
    assert local_provider(settings) is None
    assert external_provider(settings) is None
    assert local_provider(Settings(_env_file=None, LLM_MODEL="model-a")) is not None


# --- anonimizator ---


def test_anonymizer_masks_inventory_addresses_domains_and_emails() -> None:
    anonymizer = Anonymizer(
        [
            InventoryEntry(
                "11111111-2222-3333-4444-555555555555", ("web-01", "10.1.2.3"), "Zespół WWW"
            ),
            InventoryEntry("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", ("web-01.firma.example",)),
        ]
    )
    text = (
        "Host web-01 (10.1.2.3) i WEB-01.firma.example, właściciel Zespół WWW. "
        "Inny adres 192.168.7.9, IPv6 fe80::1ff:fe23:4567:890a, serwis intranet.corp.example, "
        "kontakt admin@firma.example. Wersja 2.4.49 zostaje."
    )
    masked = anonymizer.mask(text)
    for secret in (
        "web-01",
        "WEB-01",
        "10.1.2.3",
        "192.168.7.9",
        "fe80::1ff:fe23:4567:890a",
        "firma.example",
        "corp.example",
        "admin@",
        "Zespół WWW",
    ):
        assert secret not in masked
    assert "asset_11111111" in masked
    assert "asset_aaaaaaaa" in masked
    assert "2.4.49" in masked
    restored = anonymizer.restore(masked)
    assert restored.startswith(
        "Host web-01 (web-01) i web-01.firma.example, właściciel Zespół WWW."
    )
    assert restored.endswith(text.split("WWW. ")[1])


def test_no_inventory_string_survives_anonymization(session: Session) -> None:
    seed_findings(session)
    entries = inventory_entries(session)
    secrets = [s for e in entries for s in (*e.names, e.owner) if s]
    assert "web-01" in secrets
    assert "172.30.99.10" in secrets
    prompt = Prompt(
        "Zasoby: " + ", ".join(secrets), "Opisz ryzyko dla: " + "; ".join(secrets), "t.v1"
    )
    anonymized = Anonymizer(entries).anonymize(prompt)
    assert isinstance(anonymized, AnonymizedPrompt)
    outgoing = (anonymized.system + anonymized.user).lower()
    for secret in secrets:
        assert secret.lower() not in outgoing


def test_anonymized_prompt_cannot_be_forged() -> None:
    with pytest.raises(TypeError, match="Anonymizer"):
        AnonymizedPrompt("s", "u", "v")


# --- model zewnętrzny ---


def external(
    handler: httpx.MockTransport | None = None, *, enabled: bool = True
) -> ExternalProvider:
    return ExternalProvider(
        enabled=enabled,
        url="https://llm.example.com/v1",
        model="zewnetrzny",
        api_key="klucz-testowy",
        client=httpx.Client(transport=handler) if handler else None,
    )


def test_external_provider_refuses_plain_prompt() -> None:
    with pytest.raises(TypeError, match="AnonymizedPrompt"):
        list(external().stream(PROMPT, max_tokens=8))


def test_external_provider_is_off_by_default() -> None:
    provider = external(enabled=False)
    assert provider.health().available is False
    with pytest.raises(ProviderError, match="wyłączony"):
        list(provider.stream(Anonymizer().anonymize(PROMPT), max_tokens=8))


def test_external_generation_sends_only_anonymized_text_and_is_audited(session: Session) -> None:
    seed_findings(session)
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer klucz-testowy"
        sent.append(request.content.decode())
        return httpx.Response(200, json={"choices": [{"message": {"content": GOOD["executive"]}}]})

    service = ExplainerService(
        session,
        CONFIG,
        provider=FakeProvider(),
        external=external(httpx.MockTransport(handler)),
        titles=TITLES,
    )
    result = service.generate(
        vulnerability(session), "executive", actor="user:admin", use_external=True
    )
    assert (result.source, result.validation, result.model) == ("model", "passed", "zewnetrzny")
    (body,) = sent
    for asset in session.scalars(select(Asset)):
        assert asset.name not in body
        assert str((asset.attributes or {}).get("address")) not in body
    entry = session.scalar(select(AuditLog).where(AuditLog.action == "explanation_generated"))
    assert entry is not None
    assert entry.inputs["external"] is True
    assert entry.inputs["provider"] == "external"
    assert "anonymized_strings" in entry.inputs


def test_external_request_without_enabled_provider_falls_back_to_template(session: Session) -> None:
    seed_findings(session)
    local = FakeProvider([GOOD["executive"]])
    service = ExplainerService(session, CONFIG, provider=local, external=None, titles=TITLES)
    result = service.generate(vulnerability(session), "executive", actor="x", use_external=True)
    assert (result.source, result.validation) == ("template", "unavailable")
    assert local.prompts == []  # żądanie zewnętrzne nie przechodzi po cichu na inny model
