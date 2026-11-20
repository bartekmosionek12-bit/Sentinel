"""Deterministyczna kontrola odpowiedzi modelu: waliduj albo odrzuć.

Model może pisać tylko o faktach z kontekstu. Każdy identyfikator CVE, numer wersji,
polecenie i link w odpowiedzi musi pochodzić z kontekstu; inaczej odpowiedź jest
odrzucana, a użytkownik dostaje wyjaśnienie z szablonu. Kontrole formy (długość,
język, wymagane sekcje) pozwalają na jedną ponowną próbę.
"""

from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import dataclass

from app.explainer.context import AudienceLimits, ExplainContext
from app.explainer.guards import (
    copies_prompt,
    downplaying,
    secret_request,
    shell_command,
    trusted_text,
    unknown_identifiers,
)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_VERSION_RE = re.compile(r"(?<![\d.])\d+(?:\.\d+)+[a-z]?(?![\w]|\.\d)")
_DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}\.\d{1,2}\.\d{4}\b")
_URL_RE = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)
_CODE_RE = re.compile(r"```(.*?)```|`([^`\n]+)`", re.DOTALL)
_WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)
_SENTENCE_END_RE = re.compile(r"[.!?…]+(?=\s|$)")
_ABBREVIATIONS_RE = re.compile(
    r"\b(?:np|tzw|tj|m\.in|itp|itd|wg|ok|pkt|nr|ww|godz)\.", re.IGNORECASE
)
SERIOUS_CVSS = 7.0
_FOREIGN_SCRIPT_RE = re.compile(r"[Ѐ-ӿ぀-ヿ㐀-鿿가-힯]")
_POLISH_DIACRITICS = set("ąćęłńóśźżĄĆĘŁŃÓŚŹŻ")
_POLISH_WORDS = frozenset(
    [
        "i",
        "w",
        "z",
        "na",
        "do",
        "że",
        "się",
        "nie",
        "jest",
        "to",
        "oraz",
        "aby",
        "przez",
        "dla",
        "lub",
        "albo",
        "od",
        "po",
        "jak",
        "co",
        "jeśli",
        "należy",
        "może",
        "która",
        "który",
        "które",
        "tej",
        "tego",
        "ten",
        "ta",
        "są",
        "być",
        "ma",
        "jej",
        "jego",
        "ich",
        "przy",
        "ze",
        "o",
        "a",
        "wersji",
        "wersja",
        "podatność",
        "podatności",
        "system",
        "systemu",
    ]
)
_ENGLISH_WORDS = frozenset(
    [
        "the",
        "and",
        "is",
        "are",
        "of",
        "this",
        "that",
        "with",
        "for",
        "which",
        "was",
        "were",
        "has",
        "have",
        "be",
        "been",
        "can",
        "could",
        "should",
        "would",
        "an",
        "it",
        "its",
        "from",
        "by",
        "not",
        "vulnerability",
        "allows",
        "attacker",
    ]
)
MIN_POLISH_RATIO = 0.12
MAX_ENGLISH_RATIO = 0.08


@dataclass(frozen=True)
class Problem:
    code: str
    message: str
    retryable: bool


@dataclass(frozen=True)
class ValidationResult:
    problems: tuple[Problem, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.problems

    @property
    def retryable(self) -> bool:
        """Ponowna próba ma sens tylko wtedy, gdy zawiodła wyłącznie forma."""
        return bool(self.problems) and all(p.retryable for p in self.problems)

    @property
    def codes(self) -> list[str]:
        return [p.code for p in self.problems]

    @property
    def messages(self) -> list[str]:
        return [p.message for p in self.problems]


def count_sentences(text: str) -> int:
    cleaned = _VERSION_RE.sub("V", _ABBREVIATIONS_RE.sub("skrót", text))
    count = len(_SENTENCE_END_RE.findall(cleaned))
    tail = _SENTENCE_END_RE.split(cleaned)[-1].strip()
    return count + (1 if tail else 0)


def _is_prefix_of_allowed(version: str, allowed: Collection[str]) -> bool:
    return any(known == version or known.startswith(version + ".") for known in allowed)


def looks_polish(text: str) -> tuple[bool, str]:
    if _FOREIGN_SCRIPT_RE.search(text):
        return False, "tekst zawiera znaki spoza alfabetu łacińskiego"
    words = [w.lower() for w in _WORD_RE.findall(text)]
    if len(words) < 5:
        return False, "za mało słów, żeby rozpoznać język"
    polish = sum(1 for w in words if w in _POLISH_WORDS) / len(words)
    english = sum(1 for w in words if w in _ENGLISH_WORDS) / len(words)
    if english > MAX_ENGLISH_RATIO:
        return False, "tekst wygląda na angielski"
    if polish < MIN_POLISH_RATIO or not _POLISH_DIACRITICS & set(text):
        return False, "tekst nie wygląda na polski"
    return True, ""


def _serious(context: ExplainContext) -> bool:
    """Podatność z KEV albo o wysokiej wadze: bagatelizowanie przeczy faktom."""
    return context.in_kev or (context.cvss_score or 0.0) >= SERIOUS_CVSS


def validate(
    text: str,
    *,
    limits: AudienceLimits,
    context: ExplainContext,
    known_cves: Collection[str],
    system_prompt: str = "",
    downplaying_phrases: Collection[str] = (),
) -> ValidationResult:
    """`known_cves`: identyfikatory z odpowiedzi, które istnieją w bazie.

    Wersje, daty i identyfikatory muszą pochodzić z faktów bez opisu CVE: opis z rejestru jest
    tekstem z zewnątrz i może zawierać wstrzyknięte polecenia (testy w `ai-tests/`).
    """
    problems: list[Problem] = []
    stripped = text.strip()
    if not stripped:
        return ValidationResult((Problem("empty", "model nie zwrócił tekstu", True),))

    # --- fakty: błąd oznacza odrzucenie bez ponownej próby ---
    for cve in dict.fromkeys(match.upper() for match in CVE_RE.findall(stripped)):
        if cve != context.cve_id.upper() or cve not in {k.upper() for k in known_cves}:
            problems.append(Problem("unknown_cve", f"{cve} nie pochodzi z kontekstu", False))
    allowed_versions = context.allowed_versions()
    without_ids = _DATE_RE.sub(" ", CVE_RE.sub(" ", stripped))
    for version in dict.fromkeys(_VERSION_RE.findall(without_ids)):
        if not _is_prefix_of_allowed(version, allowed_versions):
            problems.append(
                Problem("unknown_version", f"wersja {version} nie pochodzi z kontekstu", False)
            )
    trusted = trusted_text(context.facts_text())
    facts_dates = set(_DATE_RE.findall(trusted))
    for found in dict.fromkeys(_DATE_RE.findall(stripped)):
        if found not in facts_dates:
            problems.append(
                Problem("unknown_date", f"data {found} nie pochodzi z kontekstu", False)
            )
    if _URL_RE.search(stripped):
        problems.append(Problem("url", "odpowiedź zawiera link spoza kontekstu", False))
    command = shell_command(stripped, context.commands)
    if command:
        problems.append(
            Problem("unknown_command", f"polecenie {command[:60]} nie pochodzi z kontekstu", False)
        )
    if secret_request(stripped):
        problems.append(Problem("secret_request", "prośba o hasło, kod albo przelew", False))
    strangers = unknown_identifiers(
        without_ids, "\n".join([trusted, *context.commands, *context.allowed_snippets()])
    )
    if strangers:
        problems.append(
            Problem(
                "unknown_identifier",
                f"identyfikator spoza kontekstu: {', '.join(strangers[:3])}",
                False,
            )
        )
    if system_prompt and copies_prompt(stripped, system_prompt):
        problems.append(Problem("prompt_leak", "fragment instrukcji systemowych w tekście", False))
    phrase = downplaying(stripped, downplaying_phrases) if _serious(context) else None
    if phrase:
        problems.append(
            Problem("contradiction", f"„{phrase}” przeczy powadze podatności z faktów", False)
        )
    allowed_snippets = context.allowed_snippets()
    facts_lower = " ".join(context.facts_text().split()).lower()
    for block, inline in _CODE_RE.findall(stripped):
        snippet = " ".join((block or inline).split()).lower()
        # Dozwolone: polecenia z listy i nazwy przepisane dosłownie z faktów (np. moduł z opisu).
        if snippet and snippet not in allowed_snippets and snippet not in facts_lower:
            problems.append(
                Problem(
                    "unknown_command", f"polecenie `{snippet[:60]}` nie pochodzi z kontekstu", False
                )
            )

    # --- forma: pozwala na jedną ponowną próbę ---
    if not limits.min_chars <= len(stripped) <= limits.max_chars:
        problems.append(
            Problem(
                "length",
                f"długość {len(stripped)} znaków poza zakresem "
                f"{limits.min_chars}–{limits.max_chars}",
                True,
            )
        )
    sentences = count_sentences(stripped)
    if not limits.min_sentences <= sentences <= limits.max_sentences:
        problems.append(
            Problem(
                "sentences",
                f"liczba zdań {sentences} poza zakresem "
                f"{limits.min_sentences}–{limits.max_sentences}",
                True,
            )
        )
    polish, why = looks_polish(stripped)
    if not polish:
        problems.append(Problem("language", why, True))
    lowered = stripped.lower()
    position = -1
    for section in limits.required_sections:
        found = lowered.find(section.lower(), position + 1)
        if found < 0:
            problems.append(
                Problem("format", f"brak sekcji „{section}” we właściwej kolejności", True)
            )
            break
        position = found
    return ValidationResult(tuple(problems))
