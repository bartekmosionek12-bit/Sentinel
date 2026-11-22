# Ochrona danych: szyfrowanie w spoczynku

Brief, wymaganie 16 i zakres minimalny: „ochrona danych z wykonanych skanów (Szyfrowanie)”.

## Co jest szyfrowane

Kod: [`backend/app/core/crypto.py`](../backend/app/core/crypto.py), migracja
`0017_encryption_at_rest`. Pola poniżej leżą w PostgreSQL jako szyfrogram
`enc:v1:<token Fernet>` (AES-128-CBC + HMAC-SHA256, losowy IV na każdy zapis). Aplikacja
szyfruje przy zapisie i odszyfrowuje przy odczycie (typy `EncryptedJSON`, `EncryptedText`).

| Tabela | Pole | Dlaczego |
|---|---|---|
| `observation` | `hostname`, `services`, `http`, `flags` | wyniki skanu: banery, wersje, nagłówki, ciasteczka, certyfikaty, dowody flag |
| `discovery_run` | `targets`, `remaining` | zakresy sieci organizacji, niezeskanowana reszta po przekroczeniu okna |
| `discovery_schedule` | `targets` | zakresy skanowane cyklicznie |
| `observation_override` | `value` | notatki, tagi i oceny ludzi |
| `finding` | `evidence` | dowody znalezisk |
| `asset` | `attributes` | atrybuty zasobów z importu |
| `software` | `raw_banner` | surowe banery usług |

Jawne zostają pola, po których baza musi wyszukiwać i łączyć tabele: adres IP obserwacji,
nazwa zasobu, produkt i wersja (dopasowanie CVE), znaczniki czasu i statusy. Poświadczeń
nie przechowujemy w ogóle (just-in-time z OpenBao, nigdy w bazie).

Test: `backend/tests/test_crypto.py` czyta surowe kolumny przez SQL i sprawdza, że nie ma
w nich jawnego tekstu. Migrację sprawdziliśmy na PostgreSQL 16 w obie strony (upgrade
szyfruje istniejące wiersze, downgrade je odszyfrowuje).

## Klucz

- `DATA_ENCRYPTION_KEY` w `.env` (poza Gitem). `scripts/ensure_env.sh` generuje go przy
  pierwszym starcie. Z klucza liczymy SHA-256 i to jest klucz Fernet.
- Klucz nie trafia do bazy, logów, odpowiedzi API ani kontekstu modelu językowego.
- **Zgubienie klucza oznacza utratę zaszyfrowanych pól.** Kopia `.env` jest częścią kopii
  zapasowej. Zły klucz kończy się błędem „DATA_ENCRYPTION_KEY nie pasuje do bazy”, a nie
  cichym zwróceniem śmieci.
- Bez klucza (tylko testy jednostkowe) aplikacja używa klucza deweloperskiego i loguje
  ostrzeżenie. `start.sh` zawsze ustawia własny klucz.

## Rotacja

1. Nowy klucz do `DATA_ENCRYPTION_KEY`, poprzedni do `DATA_ENCRYPTION_KEYS_OLD` (lista po
   przecinku).
2. Restart `api` i workerów. Odczyt działa oboma kluczami, nowe zapisy idą nowym.
3. Stare wartości przechodzą na nowy klucz przy kolejnym zapisie (np. kolejnym skanie).

## Warstwa niżej

Szyfrowanie pól chroni dane przed odczytem kopii bazy, zrzutu `pg_dump` i przed kimś, kto
ma dostęp tylko do wolumenu PostgreSQL. Wdrożenie produkcyjne powinno dodatkowo szyfrować
dysk lub wolumen (LUKS, szyfrowanie wolumenów chmury) i kopie zapasowe.
