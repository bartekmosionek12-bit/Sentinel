# Przewodnik demo

Dwie formy pokazu: **na żywo** (część 1, scenariusze w [DEMO.md](DEMO.md)) i **film 60 s**
prowadzony przez Sentka (część 2, moduł 22). Film jest planem A na scenę z ograniczonym
czasem; pokaz na żywo jest planem B i materiałem do pytań jury.

## Część 1. Pokaz na żywo

1. `./scripts/seed_demo.sh`, potem `python3 scripts/check_demo.py http://localhost:8080`.
   Skrypt loguje się jak przeglądarka (Keycloak, hasło, TOTP) i sprawdza ścieżkę krytyczną,
   w tym Sentka i prośbę menedżera o skan.
2. Scenariusze krok po kroku: [DEMO.md](DEMO.md) (zero-day, agent z certyfikatem SSH, odmowa
   dostępu menedżera, zatruty host i test agenta).
3. Konsola menedżera: samouczek (przycisk „Samouczek” w nagłówku), Sentek (przycisk „Zapytaj
   Sentka”), mapa organizacji (`/dashboard/mapa`).

## Część 2. Film 60 s z Sentkiem (moduł 22)

### Zasady

- Sentek to własny projekt (tarcza z wizjerem, antena, krótkie ręce), nie przypomina znanych
  postaci. Rysuje go kod (SVG i CSS w `frontend/shared/src/components/Sentek.tsx`).
- Lektor to lokalny syntezator Piper z głosem o licencji CC0. Nie klonujemy głosu żadnej
  realnej osoby. Bez muzyki: muzyka tylko z licencją, która na to pozwala, a domyślnie żadnej.
- Film pokazuje prawdziwą aplikację na danych demo. Nic nie jest dorysowane: podświetlenie i
  dymki to nakładka w przeglądarce, a zero-day przychodzi na żywo w trakcie nagrania.
- Klipy, nagrania, środowisko i model lektora są poza Gitem (`demo/out/`, `demo/.venv-tts/`,
  `demo/.models/` w `.gitignore`).

### Sceny

Jeden plik steruje wszystkim: [`demo/script.yaml`](../demo/script.yaml). Narracja to wersja
robocza do podmiany na tekst docelowy.

| Czas | Scena | Ekran | Co widać |
|------|-------|-------|----------|
| 0–7 s | powitanie | dashboard `/` | Sentek macha, dymek powitalny |
| 7–16 s | przejrzystość | dashboard `/mapa` | mapa organizacji, urządzenia bez rejestru |
| 16–25 s | zero-day | dashboard `/` | wpis KEV wstrzyknięty w trakcie sceny, baner zero-day |
| 25–34 s | raport | dashboard `/skrzynka` | raport zero-day, „W skrócie” (pięć odpowiedzi) |
| 34–44 s | bezpieczny agent | admin `/agent` | zadanie po zgodzie admina, po 5 s lease certyfikatu SSH 15 min |
| 44–53 s | odporność | admin `/agent/test` | test bezpieczeństwa agenta zaliczony i podpisany |
| 53–60 s | koniec | dashboard `/` | plansza „Sentinel ASI · Lokalnie · bez GPU · KSC i RODO” |

### Tryb nagrywania

`?demo=record` w adresie włącza nakładkę `DemoStage` (Sentek, dymek, podświetlenie elementu,
plansza końcowa) i ukrywa przycisk Sentka oraz samouczek. Działa wyłącznie, gdy backend
zgłasza `demo_mode` (`DEMO_MODE=true`); bez tego parametr jest ignorowany. Nagrywarka steruje
nakładką przez `window.sentinelDemo.scene({...})`, a podświetlić można tylko element z
atrybutem `data-demo` (pilnuje tego `scripts/demo_script.py check`).

### Jak nagrać

```bash
./scripts/seed_demo.sh                                # świeży stan (zero-day jeszcze nie przyszedł)
python3 scripts/demo_stage.py http://localhost:8080   # test agenta, zadanie z lease SSH
./scripts/demo_tts.sh                                 # lektor: demo/out/audio/<scena>.wav
./scripts/record_demo.sh                              # klipy 1920×1080: demo/out/clips/
./scripts/assemble_demo.sh                            # demo/out/demo.mp4 i demo/out/demo.srt
```

- `demo_stage.py` działa przez API jako `admin` (hasło i TOTP): jeśli trzeba, zleca szybki
  test agenta, tworzy zadanie „Zbierz listę zainstalowanego oprogramowania z app-01 przez
  SSH”, zatwierdza je z powodem i czeka na lease. To ta sama ścieżka co w konsoli (RBAC,
  `scope_guard`, audyt). Ostrzega, gdy raport zero-day już jest w skrzynce.
- `record_demo.sh` loguje się przez prawdziwy Keycloak (menedżer, admin z TOTP), nagrywa każdą
  scenę jako osobny klip i zapisuje moment startu sceny w `clips.json`. Przy scenie zero-day
  wypisuje, po ilu milisekundach od wstrzyknięcia pojawił się baner.
- Poprawka jednej sceny: `ONLY=raport ./scripts/record_demo.sh`, potem znów montaż. Scena
  zero-day działa raz na stan; do ponownego nagrania potrzebny jest świeży `seed_demo.sh`.
- Montaż: każda scena przycięta do swojej długości, 30 kl./s, H.264 (CRF 20), dźwięk AAC
  48 kHz, lektor dopełniony ciszą. Napisy w osobnym pliku `.srt` (nie wypalone w obrazie).
  Skrypt kończy się błędem, gdy film ma ponad 60 s. `NO_AUDIO=1` daje wersję bez lektora.
- Potrzebne: Node 22 z zależnościami `frontend/`, przeglądarka Chromium dla Playwright
  (`npx playwright install chromium` albo `CHROMIUM=/ścieżka`), `ffmpeg` i `ffprobe`.

### Lektor (Piper) i licencja głosu

- Głos `pl_PL-darkman-medium` z `rhasspy/piper-voices`. Według dokumentacji Pipera głosy
  dostrajane z bazy „lessac” mają licencję tylko do badań; darkman jest na liście głosów
  przetrenowanych na nowej bazie. Pobrana kopia (21.11.2026) ma w `MODEL_CARD`: dane CC0,
  „Finetuned from the rdh base model (… CC0)”, sha256 modelu
  `cf757ee307e3a7c23d5d8f69934deab51683d01c1c6be376d3e13146020f1530`.
- `demo_tts.sh` odmawia generowania, jeśli pobrana karta modelu wspomina „lessac”, i wypisuje
  licencję oraz sumę SHA-256 przy każdym uruchomieniu.
- Silnik Piper (`piper-tts==1.8.0`, GPL-3.0) instalujemy w osobnym `demo/.venv-tts`; służy
  tylko do wygenerowania plików audio i nie jest częścią produktu.
- Tempo `LENGTH_SCALE=0.92` (domyślnie). Skrypt sprawdza, czy lektor każdej sceny mieści się
  w jej czasie. Próba z narracją roboczą: od 6,2 s do 9,7 s na scenę, wszystkie się mieszczą.

### Co sprawdza CI

- `backend/tests/test_demo_script.py`: sceny ciągłe, łącznie ≤ 60 s, każda scena ma narrację
  (źródło lektora i napisów), najwyżej 2,6 słowa na sekundę, tylko znane akcje, pozy i
  aplikacje, podświetlenia wyłącznie przez `data-demo`, plansza końcowa, poprawne `.srt`.
- `frontend/e2e/demo.spec.ts` (Playwright na atrapie API): każda scena w trybie nagrywania ma
  swój podświetlany element w DOM (także element z `then`), plansza końcowa się pokazuje, a
  bez `DEMO_MODE` tryb nagrywania się nie włącza.
- Czego CI nie robi: nie nagrywa filmu i nie generuje lektora (pełny stos z Keycloakiem i
  model głosu). Długość lektora sprawdza `demo_tts.sh` lokalnie.

### Plan B

- Nagranie się nie udało: pokaz na żywo według części 1; te same ekrany, te same dane.
- Brak lektora: `NO_AUDIO=1 ./scripts/assemble_demo.sh` i czytanie narracji na żywo
  (`python3 scripts/demo_script.py lines`), napisy z `demo.srt`.
- Zero-day już wstrzyknięty: scena pokaże baner od razu (`demo_stage.py` o tym ostrzega);
  albo świeży `seed_demo.sh`, albo nagranie tylko tej sceny po nim.

### Głębsze nurkowanie (20–30 s każde)

Osobne krótkie klipy na pytania jury, nagrywane tym samym mechanizmem scen. Nagrywamy tylko
to, co już działa; `ready_after` w `demo/script.yaml` mówi, od którego etapu.

| Klip | Czas | Gotowe | Co pokazać |
|------|------|--------|------------|
| RBAC i redakcja danych | 25 s | teraz | menedżer na `/admin/`: odmowa i `access_denied` w audycie; pseudonimy w konsoli menedżera |
| Kill switch agenta | 25 s | teraz | czerwony przycisk z powodem; karta skutków: baza, Keycloak, OpenBao, mcp-scanner; luka 15 min dla wydanych certyfikatów |
| Samouczek i Sentek | 20 s | teraz | samouczek (9 kroków), pytanie do Sentka, odmowa polecenia „wyłącz skaner” |
| Zgodność: KSC, RODO art. 32, ISO 27001 | 30 s | po Etapie 7 | widok zgodności z linkiem do przepisu; treść wymagań z reguł, nie z modelu |
| Widok z zewnątrz (Artemis) | 25 s | po Etapie 8 | wyniki Artemis z przypisaniem CERT Polska, ten sam `scope_guard` |
