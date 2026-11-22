"""Rozpoznawanie intencji: model lokalny (JSON według schematu), a gdy go brak, gdy nie
zdąży albo odpowie nie na temat, słowa kluczowe. Parametry z modelu przechodzą przez te
same wyszukiwarki co słowa kluczowe, więc model nie wprowadzi nazwy, której nie ma w bazie.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from app.assistant.text import Named, best_match, find_cve, has_stem, normalize, words
from app.explainer.prompts import Prompt, load_template
from app.explainer.providers import LLMProvider, ProviderError

INTENTS = (
    "top_risks",
    "devices",
    "device_story",
    "explain",
    "exposure_check",
    "deadlines",
    "scan_request",
    "tour",
    "kev_list",
    "port_search",
    "system_status",
    "audit_logins",
    "out_of_scope",
)
# Intencje rozpoznawane tylko słowami kluczowymi (pytania o konkretne dane z bazy):
# model lokalny ich nie zna, więc przy nich wynik słów kluczowych ma pierwszeństwo.
KEYWORD_ONLY = frozenset({"kev_list", "port_search", "system_status", "audit_logins"})
SOURCE_MODEL = "model"
SOURCE_KEYWORDS = "keywords"

INTENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "intent": {"type": "string", "enum": list(INTENTS)},
        "device": {"type": ["string", "null"]},
        "cve": {"type": ["string", "null"]},
        "product": {"type": ["string", "null"]},
        "term": {"type": ["string", "null"]},
        "unknown_devices": {"type": "boolean"},
    },
    "required": ["intent"],
}


@dataclass(frozen=True)
class Catalog:
    """Nazwy z bazy, w których szukamy parametrów pytania."""

    devices: Sequence[Named] = ()
    products: Sequence[Named] = ()
    terms: Sequence[Named] = ()


@dataclass(frozen=True)
class Intent:
    name: str
    source: str
    device: Named | None = None
    cve: str | None = None
    product: Named | None = None
    term: Named | None = None
    unknown: bool = False
    port: int | None = None
    critical: bool = False
    # Dla out_of_scope: "action" (prośba o zmianę albo skan poza zakresem) lub "unknown".
    reason: str = ""
    # Czas pracy modelu, gdy go pytaliśmy (także gdy ostatecznie wygrały słowa kluczowe).
    model_ms: int | None = None
    notes: list[str] = field(default_factory=list)

    def params(self) -> dict[str, Any]:
        """Parametry do audytu: klucze i nazwy z bazy, nigdy surowy tekst pytania."""
        out: dict[str, Any] = {}
        for key in ("device", "product", "term"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value.name
        if self.cve:
            out["cve"] = self.cve
        if self.unknown:
            out["unknown"] = True
        if self.port is not None:
            out["port"] = self.port
        if self.critical:
            out["critical"] = True
        if self.reason:
            out["reason"] = self.reason
        return out


# Rdzenie słów po normalizacji (bez polskich znaków). Kolejność intencji w KEYWORDS
# rozstrzyga remisy: bardziej szczegółowe pytania wygrywają z ogólnymi.
KEYWORDS: dict[str, tuple[str, ...]] = {
    "tour": (
        "samouczek",
        "jak to dziala",
        "jak dziala",
        "jak korzystac",
        "jak uzywac",
        "oprowadz",
        "pokaz mi konsole",
        "pomoc",
        "instrukcj",
        "przewodnik",
    ),
    "audit_logins": (
        "logowal",
        "zalogowa",
        "logowan",
        "kto ostatnio",
        "kto byl",
        "kto wchodzil",
    ),
    "system_status": (
        "ostatni skan",
        "ostatnio skan",
        "kiedy byl",
        "feed",
        "stan systemu",
        "system",
        "czy dziala",
        "dzialaj",
        "synchroniz",
        "baza danych",
        "kolejk",
    ),
    "kev_list": ("kev", "cisa", "aktywnie wykorzyst", "wykorzystywan"),
    "port_search": ("port",),
    "scan_request": (
        "skan",
        "przeskan",
        "zeskan",
        "sprawdz ponownie",
        "nowe dane",
        "odswiez dane",
        "aktualne dane",
        "popros o",
    ),
    "explain": (
        "co to",
        "co znaczy",
        "co oznacza",
        "czym jest",
        "wyjasn",
        "wytlumacz",
        "znaczy",
        "definicj",
    ),
    "exposure_check": (
        "podatn",
        "narazen",
        "dotyczy nas",
        "czy mamy",
        "czy jestesmy",
        "czy nas",
        "u nas",
        "zagrozeni",
        "czy uzywamy",
    ),
    "deadlines": (
        "do kiedy",
        "na kiedy",
        "termin",
        "deadline",
        "zalegl",
        "spozni",
        "ile czasu",
        "kiedy naprawic",
        "kiedy trzeba",
    ),
    "device_story": (
        "opowiedz",
        "historia",
        "co z ",
        "co sie dzieje z",
        "karta",
        "szczegol",
        "co wiemy",
        "co wiesz",
    ),
    "devices": (
        "urzadzen",
        "komputer",
        "laptop",
        "sprzet",
        "serwer",
        "drukark",
        "nieznan",
        "shadow",
        "ile mamy",
        "inwentarz",
        "kamer",
    ),
    "top_risks": (
        "zagroz",
        "ryzyk",
        "najgorsz",
        "najwazniejsz",
        "najgrozniejsz",
        "krytyczn",
        "priorytet",
        "naprawi",
        "najpierw",
        "stan bezpieczenstwa",
        "problem",
        "pali sie",
        "martwic",
        "co jest zle",
        "podsumuj",
        "risk score",
        "najwyzsz",
        "cve",
    ),
}
# Prośby o zmianę, których Sentek nie wykonuje (ustawienia, inwentarz, zakres, role).
# Wygrywają z każdą intencją, także z prośbą o skan („dodaj sieć do zakresu skanowania”).
# Całe słowa (tryb rozkazujący i bezokolicznik), żeby „co się zmieniło?” nie było odmową.
_VERBS = {
    "wylacz": "wylaczyc",
    "wlacz": "wlaczyc",
    "zmien": "zmienic",
    "usun": "usunac",
    "skasuj": "skasowac",
    "zaktualizuj": "zaktualizowac",
    "zainstaluj": "zainstalowac",
    "zablokuj": "zablokowac",
    "odblokuj": "odblokowac",
    "zrestartuj": "zrestartowac",
    "nadaj": "nadac",
    "dodaj": "dodac",
    "zignoruj": "zignorowac",
    "wykonaj": "wykonac",
    "edytuj": "edytowac",
    "ustaw": "ustawic",
    "napraw": "",
}
ACTION_WORDS = frozenset(
    word for imp, inf in _VERBS.items() for word in (imp, f"{imp}cie", inf) if word
)
# „Uruchom” jest w porządku tylko przy skanie (wtedy i tak tylko prośba) i samouczku.
SOFT_ACTION_WORDS = frozenset({"uruchom", "uruchomcie", "uruchomic", "odpal", "odpalcie"})
_PORT_RE = re.compile(r"\bport\w*\s*(?:nr\.?\s*)?(\d{1,5})\b|\b(\d{1,5})\s*/\s*(?:tcp|udp)\b")
# Słowa o urządzeniach nieznanych (shadow IT).
UNKNOWN_STEMS = ("nieznan", "shadow", "obce", "niezgloszon", "nieautoryz")


def find_params(text: str, catalog: Catalog) -> dict[str, Any]:
    term = best_match(text, catalog.terms, threshold=95)
    return {
        "cve": find_cve(text),
        "device": best_match(text, catalog.devices),
        "product": best_match(text, catalog.products, threshold=92),
        "term": term,
        "unknown": has_stem(words(text), UNKNOWN_STEMS) > 0,
        "port": find_port(text),
        "critical": has_stem(words(text), ("krytyczn",)) > 0,
    }


def find_port(text: str) -> int | None:
    match = _PORT_RE.search(normalize(text))
    if not match:
        return None
    port = int(match[1] or match[2])
    return port if 0 < port <= 65535 else None


def classify_keywords(text: str, catalog: Catalog) -> Intent:
    tokens = words(text)
    params = find_params(text, catalog)
    scores = {name: has_stem(tokens, stems) for name, stems in KEYWORDS.items()}
    # Parametry podpowiadają intencję: nazwa urządzenia → karta, CVE → wyjaśnienie/narażenie.
    if params["device"] is not None:
        scores["device_story"] += 1
    if params["cve"] or params["product"]:
        scores["exposure_check"] += 1 if scores["explain"] == 0 else 0
    if params["term"] is not None and not params["cve"] and not params["unknown"]:
        scores["explain"] += 1
    if params["unknown"]:
        scores["devices"] += 1
    if params["port"] is not None:
        scores["port_search"] += 1
    # Prośba o skan wygrywa z pytaniem o urządzenia, gdy pada słowo o skanowaniu.
    if scores["scan_request"]:
        scores["scan_request"] += 1
    # „Kiedy był ostatni skan?” to pytanie o stan, nie prośba o skan.
    if scores["system_status"] and not has_stem(tokens, ("przeskan", "zeskan", "zaproponuj")):
        scores["scan_request"] = 0
    # „Które podatności są w CISA KEV?” to lista, a „co to jest KEV?” to wyjaśnienie.
    if scores["kev_list"] and scores["explain"] and has_stem(tokens, ("co to", "co znaczy")):
        scores["kev_list"] = 0
    best = max(scores, key=lambda name: scores[name])
    if ACTION_WORDS & set(tokens) or (
        SOFT_ACTION_WORDS & set(tokens) and not scores["scan_request"] and not scores["tour"]
    ):
        return Intent("out_of_scope", SOURCE_KEYWORDS, reason="action")
    if scores[best] == 0:
        return Intent("out_of_scope", SOURCE_KEYWORDS, reason="unknown")
    return _resolve(Intent(best, SOURCE_KEYWORDS), params)


def _resolve(intent: Intent, params: dict[str, Any]) -> Intent:
    """Dokłada parametry i sprawdza, czy intencja ma to, czego potrzebuje."""
    intent = replace(
        intent,
        device=params.get("device"),
        cve=params.get("cve"),
        product=params.get("product"),
        term=params.get("term"),
        unknown=bool(params.get("unknown")),
        port=params.get("port"),
        critical=bool(params.get("critical")),
    )
    if intent.name == "device_story" and intent.device is None:
        return replace(intent, name="devices")
    if intent.name == "explain" and intent.term is None and intent.cve is None:
        return replace(intent, name="out_of_scope", reason="unknown")
    if intent.name == "exposure_check" and intent.cve is None and intent.product is None:
        return replace(intent, name="top_risks")
    if intent.name == "port_search" and intent.port is None:
        return replace(intent, name="devices")
    return intent


class ModelClassifier:
    """Model lokalny z krótkim limitem czasu. Każdy błąd oznacza powrót do słów kluczowych."""

    def __init__(self, provider: LLMProvider | None, *, timeout_seconds: float = 4.0) -> None:
        self._provider = provider
        self._timeout = timeout_seconds

    def prompt(self, text: str, catalog: Catalog) -> Prompt:
        facts = json.dumps(
            {
                "pytanie": text,
                "terminy": [t.name for t in catalog.terms],
            },
            ensure_ascii=False,
        )
        rendered = load_template("assistant_intent").render(facts)
        return replace(rendered, schema=INTENT_SCHEMA)

    def _ask(self, provider: LLMProvider, prompt: Prompt) -> dict[str, Any]:
        deadline = time.monotonic() + self._timeout
        parts: list[str] = []
        for chunk in provider.stream(prompt, max_tokens=120):
            parts.append(chunk)
            if time.monotonic() > deadline:
                raise ProviderError("Model nie zdążył w limicie czasu asystenta")
        data = json.loads("".join(parts))
        if not isinstance(data, dict) or data.get("intent") not in INTENTS:
            raise ValueError("Odpowiedź modelu poza schematem")
        return data

    def classify(self, text: str, catalog: Catalog) -> Intent:
        fallback = classify_keywords(text, catalog)
        if self._provider is None or fallback.name in KEYWORD_ONLY:
            return fallback
        started = time.monotonic()
        try:
            data = self._ask(self._provider, self.prompt(text, catalog))
        except (ProviderError, ValueError, TypeError):
            elapsed = int((time.monotonic() - started) * 1000)
            return replace(fallback, model_ms=elapsed, notes=["model niedostępny"])
        elapsed = int((time.monotonic() - started) * 1000)
        if fallback.reason == "action":
            # Prośba o zmianę albo naprawę: odmowa niezależnie od tego, co uznał model.
            return replace(fallback, model_ms=elapsed)
        # Parametry z tekstu pytania mają pierwszeństwo; z modelu bierzemy tylko to, co
        # da się odnaleźć w bazie (model nie wprowadzi nazwy spoza katalogu).
        params = find_params(text, catalog)
        for key, pool in (
            ("device", catalog.devices),
            ("product", catalog.products),
            ("term", catalog.terms),
        ):
            value = data.get(key)
            if params[key] is None and isinstance(value, str) and value.strip():
                params[key] = best_match(value, pool, threshold=92)
        if params["cve"] is None and isinstance(data.get("cve"), str):
            params["cve"] = find_cve(data["cve"])
        params["unknown"] = params["unknown"] or data.get("unknown_devices") is True
        intent = _resolve(Intent(str(data["intent"]), SOURCE_MODEL, model_ms=elapsed), params)
        if intent.name == "out_of_scope" and fallback.name != "out_of_scope":
            # Model odmówił, a słowa kluczowe rozpoznały pytanie: lepiej odpowiedzieć z danych.
            return replace(fallback, model_ms=elapsed, notes=["model nie rozpoznał pytania"])
        if intent.name == "out_of_scope":
            return replace(intent, reason=fallback.reason or "unknown")
        return intent
