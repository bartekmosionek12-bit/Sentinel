"""Szyfrowanie pól wrażliwych w spoczynku (brief, wymaganie 16).

Wyniki skanów (nazwy hostów, usługi, odpowiedzi HTTP, flagi z dowodami), cele przebiegów,
notatki i nadpisania człowieka, dowody findingów, banery i atrybuty zasobów zapisujemy w bazie
jako szyfrogram Fernet (AES-128-CBC + HMAC-SHA256). Klucz pochodzi z `DATA_ENCRYPTION_KEY`
w `.env` (generuje go `scripts/ensure_env.sh`), nigdy nie trafia do bazy, logów ani API.

Rotacja: `DATA_ENCRYPTION_KEYS_OLD` (lista po przecinku) odszyfrowuje stare wartości, a nowe
zapisy idą zawsze nowym kluczem (MultiFernet). Wartość bez prefiksu `enc:v1:` to dane sprzed
migracji 0017: odczytujemy je jako jawne, a przy następnym zapisie zostaną zaszyfrowane.

Pola, po których baza musi wyszukiwać i łączyć tabele (adres IP, nazwa zasobu, produkt
i wersja do dopasowania CVE), zostają jawne; opis w docs/SECURITY.md.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from functools import lru_cache
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from sqlalchemy import Text
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator

from app.core.config import get_settings

logger = logging.getLogger("sentinel.crypto")
PREFIX = "enc:v1:"
# Tylko dla testów i pracy lokalnej bez .env; start.sh zawsze ustawia własny klucz.
DEV_KEY = "sentinel-dev-key-not-for-production"


class DecryptionError(RuntimeError):
    """Szyfrogram nie pasuje do żadnego znanego klucza (zły albo zgubiony klucz)."""


def _fernet(secret: str) -> Fernet:
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


@lru_cache
def cipher() -> MultiFernet:
    settings = get_settings()
    primary = settings.data_encryption_key
    if not primary:
        logger.warning("Brak DATA_ENCRYPTION_KEY: używam klucza deweloperskiego (tylko testy)")
        primary = DEV_KEY
    old = [k.strip() for k in settings.data_encryption_keys_old.split(",") if k.strip()]
    return MultiFernet([_fernet(primary), *(_fernet(k) for k in old)])


def encrypt(text: str) -> str:
    return PREFIX + cipher().encrypt(text.encode("utf-8")).decode("ascii")


def decrypt(value: str) -> str:
    if not value.startswith(PREFIX):
        return value  # dane sprzed migracji 0017
    try:
        return cipher().decrypt(value[len(PREFIX) :].encode("ascii")).decode("utf-8")
    except InvalidToken as error:
        raise DecryptionError(
            "Nie da się odszyfrować danych: DATA_ENCRYPTION_KEY nie pasuje do bazy"
        ) from error


def is_encrypted(value: object) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


class EncryptedText(TypeDecorator[str]):
    """Tekst zapisany w bazie jako szyfrogram."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect: Dialect) -> str | None:
        return None if value is None else encrypt(value)

    def process_result_value(self, value: str | None, dialect: Dialect) -> str | None:
        return None if value is None else decrypt(value)


class EncryptedJSON(TypeDecorator[Any]):
    """Struktura JSON zapisana w bazie jako szyfrogram (po stronie Pythona: dict albo list)."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Dialect) -> str | None:
        if value is None:
            return None
        return encrypt(json.dumps(value, ensure_ascii=False, separators=(",", ":")))

    def process_result_value(self, value: Any, dialect: Dialect) -> Any:
        if value is None:
            return None
        if not isinstance(value, str):
            return value  # kolumna JSON sprzed migracji (sterownik oddał już strukturę)
        return json.loads(decrypt(value))
