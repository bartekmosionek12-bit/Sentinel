"""Wyjaśnienia podatności: generuj raz, waliduj albo odrzuć, zawsze miej szablon.

Klucz cache: `typ + CVE + poziom odbiorcy + wersja promptu`. Dla jednego CVE powstają
najwyżej trzy teksty, niezależnie od liczby dotkniętych zasobów. Dane zasobu dokleja
kod (`asset_header`), więc nazwy hostów nie trafiają do modelu.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.explainer.anonymizer import Anonymizer, inventory_entries
from app.explainer.context import ExplainContext, ExplainerConfig, build_context
from app.explainer.fallback import render_fallback
from app.explainer.prompts import Prompt, load_template
from app.explainer.providers import LLMProvider, LLMResult, ProviderError, generate
from app.explainer.validator import CVE_RE, ValidationResult, validate
from app.models import Asset, Finding, LLMCache, Software, Vulnerability
from app.models.ops import AUDIENCES

KIND = "cve_explanation"
MAX_ATTEMPTS = 2
SOURCE_MODEL = "model"
SOURCE_TEMPLATE = "template"
EXPOSURE_LABELS = {"internet": "dostępny z internetu", "internal": "tylko w sieci wewnętrznej"}


@dataclass(frozen=True)
class Explanation:
    cve_id: str
    audience: str
    text: str
    source: str  # model | template
    cached: bool
    # passed: tekst modelu po walidacji; rejected: odpowiedź odrzucona, tekst z szablonu;
    # none: modelu nie pytano; unavailable: model nie odpowiedział.
    validation: str
    prompt_version: str
    model: str | None = None
    problems: tuple[str, ...] = ()
    created_at: datetime | None = None
    tokens: int | None = None
    duration_ms: int | None = None

    @property
    def label(self) -> str:
        if self.source == SOURCE_MODEL:
            return f"Wygenerowane przez model {self.model}, sprawdzone automatycznie"
        reasons = {
            "rejected": "odpowiedź modelu nie przeszła kontroli",
            "unavailable": "model jest niedostępny",
            "none": "model nie był pytany",
        }
        return f"Wersja automatyczna z szablonu ({reasons.get(self.validation, 'bez modelu')})"


@dataclass
class Listener:
    """Odbiorca zdarzeń generowania (np. strumień do interfejsu)."""

    on_token: Callable[[str], None] = field(default=lambda _token: None)
    on_retry: Callable[[], None] = field(default=lambda: None)


def cache_key(cve_id: str, audience: str, prompt_version: str) -> str:
    return f"{KIND}:{cve_id}:{audience}:{prompt_version}"


def template_name(audience: str) -> str:
    return f"explain_{audience}"


class ExplainerService:
    def __init__(
        self,
        session: Session,
        config: ExplainerConfig,
        *,
        provider: LLMProvider | None = None,
        external: LLMProvider | None = None,
        titles: dict[tuple[str, str], str] | None = None,
    ) -> None:
        self._session = session
        self._config = config
        self._provider = provider
        self._external = external
        self._titles = titles or {}

    # --- odczyt ---

    def context(self, vuln: Vulnerability) -> ExplainContext:
        return build_context(vuln, self._config, self._titles)

    def _row(self, cve_id: str, audience: str) -> LLMCache | None:
        version = load_template(template_name(audience)).version
        return self._session.scalar(
            select(LLMCache).where(LLMCache.cache_key == cache_key(cve_id, audience, version))
        )

    @staticmethod
    def _from_row(cve_id: str, row: LLMCache) -> Explanation:
        passed = row.validation == "passed"
        return Explanation(
            cve_id=cve_id,
            audience=row.audience,
            text=row.content,
            source=SOURCE_MODEL if passed else SOURCE_TEMPLATE,
            cached=True,
            validation=row.validation,
            prompt_version=row.prompt_version,
            model=row.model,
            created_at=row.created_at,
            tokens=row.tokens,
            duration_ms=row.duration_ms,
        )

    def _template(
        self,
        context: ExplainContext,
        audience: str,
        validation: str,
        problems: tuple[str, ...] = (),
    ) -> Explanation:
        return Explanation(
            cve_id=context.cve_id,
            audience=audience,
            text=render_fallback(context, audience),
            source=SOURCE_TEMPLATE,
            cached=False,
            validation=validation,
            prompt_version=load_template(template_name(audience)).version,
            problems=problems,
        )

    def get(self, vuln: Vulnerability, audience: str) -> Explanation:
        """Tekst z cache albo z szablonu. Nigdy nie wywołuje modelu."""
        _check_audience(audience)
        row = self._row(vuln.cve_id, audience)
        if row is not None:
            return self._from_row(vuln.cve_id, row)
        return self._template(self.context(vuln), audience, "none")

    # --- generowanie ---

    def generate(
        self,
        vuln: Vulnerability,
        audience: str,
        *,
        actor: str,
        regenerate: bool = False,
        use_external: bool = False,
        listener: Listener | None = None,
    ) -> Explanation:
        """Zwraca tekst z cache albo generuje go raz. Zapis i audit w bieżącej transakcji."""
        _check_audience(audience)
        listener = listener or Listener()
        row = self._row(vuln.cve_id, audience)
        if row is not None and not regenerate:
            return self._from_row(vuln.cve_id, row)

        context = self.context(vuln)
        limits = self._config.audiences[audience]
        prompt = load_template(template_name(audience)).render(context.facts_text())
        provider = self._external if use_external else self._provider
        base_inputs = {
            "cve_id": vuln.cve_id,
            "audience": audience,
            "prompt_version": prompt.version,
            "context_sha256": context.digest,
            "provider": getattr(provider, "name", None),
            "model": getattr(provider, "model", None),
            "external": use_external,
        }
        if provider is None:
            self._audit(
                actor, "explanation_unavailable", vuln, base_inputs, "Model nie jest skonfigurowany"
            )
            return self._template(
                context, audience, "unavailable", ("model nie jest skonfigurowany",)
            )

        anonymizer: Anonymizer | None = None
        outgoing: Prompt = prompt
        if use_external:
            # Do zewnętrznego modelu wychodzi wyłącznie tekst po anonimizacji.
            anonymizer = Anonymizer(inventory_entries(self._session))
            outgoing = anonymizer.anonymize(prompt)
            base_inputs["anonymized_strings"] = anonymizer.replaced

        result: LLMResult | None = None
        verdict = ValidationResult()
        attempts = 0
        try:
            while attempts < MAX_ATTEMPTS:
                attempts += 1
                if attempts > 1:
                    listener.on_retry()
                result = generate(
                    provider, outgoing, max_tokens=limits.max_tokens, on_token=listener.on_token
                )
                text = anonymizer.restore(result.text) if anonymizer else result.text
                result = LLMResult(
                    text, result.model, result.tokens, result.duration_ms, result.first_token_ms
                )
                verdict = validate(
                    text, limits=limits, context=context, known_cves=self._known_cves(text)
                )
                if verdict.ok or not verdict.retryable:
                    break
        except ProviderError as error:
            self._audit(
                actor,
                "explanation_unavailable",
                vuln,
                {**base_inputs, "attempts": attempts, "error": str(error)},
                "Model nie odpowiedział; pokazano wyjaśnienie z szablonu",
            )
            return self._template(context, audience, "unavailable", (str(error),))

        assert result is not None  # noqa: S101 - pętla wykonała się co najmniej raz
        passed = verdict.ok
        content = result.text if passed else render_fallback(context, audience)
        if row is None:
            row = LLMCache(
                cache_key=cache_key(vuln.cve_id, audience, prompt.version),
                kind=KIND,
                audience=audience,
                prompt_version=prompt.version,
                content=content,
                model=result.model,
            )
            self._session.add(row)
        row.content = content
        row.model = result.model
        row.tokens = result.tokens
        row.duration_ms = result.duration_ms
        row.validation = "passed" if passed else "rejected"
        self._session.flush()
        self._audit(
            actor,
            "explanation_generated" if passed else "explanation_rejected",
            vuln,
            {
                **base_inputs,
                "attempts": attempts,
                "tokens": result.tokens,
                "duration_ms": result.duration_ms,
                "problems": verdict.codes,
            },
            (
                "Wyjaśnienie wygenerowane przez model i zaakceptowane przez walidator"
                if passed
                else "Odpowiedź modelu odrzucona przez walidator: "
                + "; ".join(verdict.messages)
                + ". Zapisano wyjaśnienie z szablonu"
            ),
        )
        explanation = self._from_row(vuln.cve_id, row)
        return Explanation(
            **{**explanation.__dict__, "cached": False, "problems": tuple(verdict.messages)}
        )

    def _known_cves(self, text: str) -> set[str]:
        found = {match.upper() for match in CVE_RE.findall(text)}
        if not found:
            return set()
        return set(
            self._session.scalars(
                select(Vulnerability.cve_id).where(Vulnerability.cve_id.in_(found))
            )
        )

    def _audit(
        self, actor: str, action: str, vuln: Vulnerability, inputs: dict[str, object], reason: str
    ) -> None:
        audit.record(
            self._session,
            audit.AuditEvent(
                actor=actor,
                action=action,
                reason=reason,
                inputs=dict(inputs),
                object_type="vulnerability",
                object_id=vuln.cve_id,
            ),
        )


def _check_audience(audience: str) -> None:
    if audience not in AUDIENCES:
        raise ValueError(f"Nieznany poziom odbiorcy: {audience}")


def asset_header(session: Session, finding: Finding) -> str:
    """Kontekst zasobu doklejany przez kod do wspólnego tekstu o CVE."""
    asset = session.get(Asset, finding.asset_id)
    if asset is None:
        return ""
    software = session.get(Software, finding.software_id) if finding.software_id else None
    parts = []
    if software is not None:
        parts.append(" ".join(filter(None, [software.product, software.version])))
    parts.append(EXPOSURE_LABELS.get(asset.exposure, asset.exposure))
    parts.append(f"krytyczność {asset.criticality}/5")
    if asset.owner:
        parts.append(f"właściciel: {asset.owner}")
    return f"Dotyczy: {asset.name} ({', '.join(parts)})."
