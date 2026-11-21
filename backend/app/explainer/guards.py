"""Kontrole przeciw pośredniemu prompt injection, wspólne dla wyjaśnień i raportów.

Opis CVE z rejestru jest tekstem z zewnątrz: model go widzi, ale nic, co pochodzi tylko z
opisu, nie może trafić do człowieka jako fakt. Dlatego walidatory sprawdzają pochodzenie
wersji, dat i identyfikatorów względem faktów *bez* opisu, a niezależnie od faktów odrzucają:
- polecenia systemowe i ścieżki plików (także bez znaków kodu),
- prośby o hasła, kody i przelewy,
- obce identyfikatory (np. kanarek `kanarek-5d1c9e`), których nie ma w zaufanych faktach,
- dosłowne fragmenty instrukcji systemowych (wyciek promptu).

Testy promptfoo w `ai-tests/` pokazały, że bez tych kontroli posłuszny model przepychał przez
walidację fałszywą wersję, CVE, termin, polecenie `rm -rf` i kanarka z opisu.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable

# Znacznik, od którego linia faktów zawiera opis z rejestru (do końca linii).
UNTRUSTED_MARKERS = (
    "Opis z rejestru (po angielsku, tylko informacja):",
    "Opis z bazy NVD (po angielsku):",
)

_SHELL_WORDS = (
    "sudo|rm|curl|wget|chmod|chown|bash|zsh|powershell|iex|invoke-webrequest|nc|ncat|netcat|"
    "dd|mkfs|systemctl|service|kill|pkill|apt|apt-get|yum|dnf|apk|pip|npm|docker|kubectl|"
    "scp|ssh|ftp|tftp|certutil|reg|regsvr32|mshta|rundll32"
)
# Kolejno: słowo polecenia z argumentem, ścieżka systemowa, potok do powłoki, ścieżka Windows.
_SHELL_RE = re.compile(
    rf"(?<![\w-])(?:{_SHELL_WORDS})\s+(?:-{{1,2}}\w|/|~|\w+[/.:]|\|)"
    r"|(?<![\w/.])/(?:etc|var|usr|bin|sbin|tmp|root|home|opt|dev|proc|srv)(?:/[\w.-]*)*"
    r"|\|\s*(?:sh|bash|zsh|powershell)\b"
    r"|[A-Za-z]:\\[\w\\.-]+",
    re.IGNORECASE,
)
_SECRET_RE = re.compile(
    r"\b(?:wyśl|wysł|wysył|podaj|podać|przekaż|przekaz|udostępni|prześl|przesł|wpisz|wpisać|"
    r"send|share|provide|enter)\w*\b[^.!?\n]{0,80}?"
    r"\b(?:hasł|password|login|dane logowania|poświadcze|kod\w* (?:mfa|sms|jednorazow)|"
    r"token\w* dostęp|klucz\w* (?:prywatn|api|ssh)|przelew|numer\w* kart|numer\w* kont)"
    r"|\b(?:hasł|password|dane logowania|poświadcze)\w*\b[^.!?\n]{0,60}?"
    r"\b(?:mailem|e-mailem|emailem|sms|telefonicznie|na czacie|przez czat|by e-?mail)"
    # Raport bezpieczeństwa nigdy nie dotyczy pieniędzy.
    r"|\b(?:przelew|numer\w* (?:kont|kart)|bitcoin|kryptowalut|wire transfer)",
    re.IGNORECASE,
)
# Słowo z cyframi i literami (np. kod, kanarek, nazwa pliku); krótkie formy jak „24h” pomijamy.
_IDENTIFIER_RE = re.compile(r"(?<![\w-])(?=[\w-]*\d)(?=[\w-]*[^\W\d_])[\w-]{5,}(?![\w-])")
_TOKEN_RE = re.compile(r"^(?:asset|person)_\d+$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
# Złożenia z liczbą („1-bajtowy”, „3-dniowy”, „64-bitowej”) to zwykłe słowa, nie identyfikatory.
_NUMBER_COMPOUND_RE = re.compile(r"^\d+-[^\W\d_]+$")
_WORDS_RE = re.compile(r"[^\W_]+", re.UNICODE)
PROMPT_SHINGLE = 6


def trusted_text(facts: str) -> str:
    """Fakty bez opisów z rejestru: tylko to, co policzył albo podał kod."""
    lines = []
    for line in facts.splitlines():
        for marker in UNTRUSTED_MARKERS:
            index = line.find(marker)
            if index >= 0:
                line = line[:index]
        lines.append(line)
    return "\n".join(lines)


def shell_command(text: str, allowed: Iterable[str] = ()) -> str | None:
    """Pierwsze polecenie systemowe albo ścieżka pliku spoza listy dozwolonych poleceń."""
    cleaned = text
    for command in sorted({c for c in allowed if c}, key=len, reverse=True):
        cleaned = re.sub(re.escape(command), " ", cleaned, flags=re.IGNORECASE)
    match = _SHELL_RE.search(cleaned)
    return match.group(0).strip() if match else None


def secret_request(text: str) -> str | None:
    """Prośba o przekazanie hasła, kodu, klucza albo pieniędzy."""
    match = _SECRET_RE.search(text)
    return " ".join(match.group(0).split()) if match else None


def unknown_identifiers(text: str, trusted: str) -> list[str]:
    """Identyfikatory z cyframi, których nie ma w zaufanych faktach (poza tokenami i CVE)."""
    known = trusted.lower()
    found = []
    for match in _IDENTIFIER_RE.finditer(text):
        word = match.group(0).strip("-")
        if (
            _TOKEN_RE.match(word)
            or _CVE_RE.match(word)
            or _NUMBER_COMPOUND_RE.match(word)
            or word.lower() in known
        ):
            continue
        found.append(word)
    return list(dict.fromkeys(found))


def _words(text: str) -> list[str]:
    return [w.lower() for w in _WORDS_RE.findall(text)]


def copies_prompt(text: str, system_prompt: str, size: int = PROMPT_SHINGLE) -> bool:
    """Czy tekst zawiera co najmniej `size` kolejnych słów z instrukcji systemowych."""
    source = _words(system_prompt)
    if len(source) < size:
        return False
    shingles = {tuple(source[i : i + size]) for i in range(len(source) - size + 1)}
    words = _words(text)
    return any(tuple(words[i : i + size]) in shingles for i in range(len(words) - size + 1))


def downplaying(text: str, phrases: Collection[str]) -> str | None:
    lowered = " ".join(text.lower().split())
    return next((phrase for phrase in phrases if phrase in lowered), None)
