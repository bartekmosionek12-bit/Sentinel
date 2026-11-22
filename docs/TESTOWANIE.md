# Jak przetestować Sentinel ASI

Stan na 2026-11-22. Wszystkie komendy wpisuj w folderze repozytorium. Windows: `.\start.cmd`
(PowerShell albo dwuklik), Linux/macOS/Git Bash: `./start.sh`.

## 0. Aktualizacja kodu

```bash
git stash                                  # lokalne zmiany (np. końce linii) na bok
git pull --ff-only origin sprint-final     # albo: git checkout main && git pull origin main
git log -1 --oneline                       # najnowszy commit z GitHuba
```

Po `pull` zawsze uruchom `start` od nowa: interfejs i API są w obrazach Dockera, więc bez
przebudowy zobaczysz starą wersję. Potem w przeglądarce Ctrl+F5.

## 1. Tryb demo (domyślny)

```bash
./start.sh            # Windows: .\start.cmd
```

Skrypt sam:

1. tworzy `.env` i hasła, ustawia `DEMO_MODE=true`,
2. uruchamia lokalne DefectDojo (pierwszy raz kilka minut), zakłada product/engagement/test
   i token, zapisuje je w `.env`,
3. buduje i uruchamia aplikację z izolowaną siecią demo-lab (`172.30.99.0/24`),
4. wykonuje skan demo, zakłada konta i czeka, aż konsola odpowiada (`/api/health` = 200).

Adresy:

| Co | Gdzie | Logowanie |
|---|---|---|
| Konsola | <http://localhost:8080/admin/> | `admin` / hasło z `data/demo-credentials.env` + TOTP |
| DefectDojo | <http://localhost:8081> | `DD_ADMIN_USER` / `DD_ADMIN_PASSWORD` z `.env` |

TOTP: sekret jest w `data/demo-credentials.env` (link `otpauth://` wypisuje też skrypt);
dodaj go do aplikacji typu Google Authenticator albo Aegis. Konta: `admin`, `editor`,
`modifier`, `viewer` (cztery role z briefu, tabela w [ROLES.md](ROLES.md)).

Jeśli DefectDojo się nie uruchomi (np. Docker Hub zwróci 429), aplikacja działa dalej, a
skrypt mówi, co zrobić (`docker login`). Eksport awaryjny: Skany → „Pobierz nmap XML”.

## 2. Wyłączenie trybu demo

```bash
./start.sh --bez-demo                 # Windows: .\start.cmd --bez-demo
./start.sh --bez-demo --czysta-baza   # to samo, ale od pustej bazy (usuwa dane z demo)
```

Tryb bez demo:

- `DEMO_MODE=false`: znika żółty pasek „Tryb demo”, `seed-demo` i `inject-kev` są
  zablokowane, kontenery demo-lab są zatrzymane,
- zakres skanowania: `rules/scope.mentor-lab.yaml`, czyli tylko komputer z labem mentorów
  (`host.docker.internal`); inny plik: `SCOPE_FILE=/app/rules/twoj.yaml ./start.sh --bez-demo`,
- DefectDojo i cztery konta z TOTP działają tak samo jak w demo,
- `--czysta-baza` usuwa wolumeny tego projektu (baza, Keycloak, DefectDojo). Bez tej flagi
  dane z wcześniejszego demo zostają widoczne na pulpicie i w zasobach.

Powrót do demo: `./start.sh`.

## 3. Dane od mentorów w konsoli

### 3a. Skan na żywo (zalecane)

1. `./start.sh --bez-demo --czysta-baza`
2. W osobnym terminalu, w folderze z rozpakowanym `lab.zip`: `./quickstart.sh up`
   (Windows bez basha: `docker compose -f docker-compose-custom-network.yml up -d flask-app gitea rabbitmq`).
   Poczekaj ok. 30 s (RabbitMQ startuje wolno).
3. Konsola → **Discovery → Przebiegi discovery** → pole **Cele**: `host.docker.internal` →
   **Sprawdź cele** → **Uruchom skan**. Przebieg trwa ok. 2 minut.
4. Otwórz przebieg: hosty, usługi (2223, 3001, 5673, 8787, 15673), fingerprint WWW
   (tytuł, kod, nagłówki, ciasteczka, TLS, przekierowania), technologie (Gitea, RabbitMQ),
   flagi (panele, staging) z dowodami.
5. `./quickstart.sh change` → drugi skan. `./quickstart.sh up` → trzeci skan.
6. **Discovery → Porównanie i stany**: w drugim przebiegu znika usługa 8787, w trzecim
   wraca; stany hostów (aktywny, niestabilny, nieaktywny).
7. Pozostałe stacki z `lab.zip` (jeden naraz, porty się pokrywają):
   `docker compose -f docker-compose-vulnerable.yml up -d` (WordPress, DVWA, vsftpd, MySQL)
   albo `-modern.yml` (WordPress, phpMyAdmin, Redis, Nginx Proxy Manager), potem skan tego
   samego celu.

Uwaga: `host.docker.internal` to cały Twój komputer, więc skan pokaże też inne opublikowane
porty (np. 8080 samej konsoli, 8081 DefectDojo).

### 3b. Import wyników zamiast skanu

Discovery → **Import wyników** przyjmuje JSON, CSV i nmap XML. Na przykład wynik nmapa z
komputera z labem:

```bash
nmap -sV -oX lab.xml -p 2223,3001,5673,8787,15673 127.0.0.1
```

Plik `lab.xml` wczytaj w konsoli; przebieg z importu jest przetwarzany tak samo jak skan.
Formularz celów (Discovery → Cele) przyjmuje listę ręczną, CSV i JSON.

### 3c. Co sprawdzić dalej

| Funkcja | Gdzie |
|---|---|
| Edycja wyniku (nazwa hosta, krytyczność, status obsługi, notatka), zachowana w kolejnych skanach | przebieg → karta hosta → pola edycji → „Zapisz zmiany” |
| Eksport wyników (JSON, CSV, nmap XML) i różnic (JSON, CSV) | przebieg → „Hosty” → przyciski formatu; Porównanie → przyciski eksportu |
| Eksport do DefectDojo (finding Info) | przebieg → zaznacz hosty → „Wyślij do DefectDojo”, potem <http://localhost:8081> |
| Własne sygnatury | Discovery → **Sygnatury detekcyjne** → YAML → Sprawdź → Zapisz → nowy skan |
| Role | zaloguj się jako `viewer`: brak przycisków zapisu, API zwraca 403 i zapisuje odmowę w audycie |
| Dziennik audytu | Kontrola → Dziennik audytu (wejścia do konsoli, skany, eksporty, sygnatury) |
| Sentek | postać w prawym dolnym rogu: najedź, kliknij, użyj szybkich akcji |

## 4. Testy automatyczne

```bash
cd backend && uv sync && uv run ruff check . && uv run mypy app && uv run pytest
cd ../frontend && npm ci && npx tsc -b && npm run build && npx playwright test --trace off
```

Test całej ścieżki demo na działającym stosie (25 asercji, w tym role, MFA, Sentek, raporty):

```bash
python scripts/check_demo.py http://localhost:8080
```

Silnik discovery bez stawiania aplikacji (na komputerze z labem, wymaga `nmap` i `uv`):
[LAB_TEST.md](LAB_TEST.md), sekcja 2.

## 5. Gdy coś nie działa

| Objaw | Co zrobić |
|---|---|
| „Nie udało się sprawdzić uprawnień: 502” | konsola sama czeka do 3 min; jeśli nie przejdzie: `docker compose ps api` i `docker compose logs --tail 50 api` |
| „Nie udało się zalogować: authentication_expired” | konsola ponawia logowanie sama; jeśli nie, „Spróbuj ponownie” |
| Stary wygląd po aktualizacji | `git log -1` (czy pull przeszedł), `./start.sh`, Ctrl+F5 |
| „Pool overlaps” przy starcie | `start.sh` sprząta starą kopię projektu sam; inną sieć usuń: `docker network rm <nazwa>` |
| DefectDojo: 429 Too Many Requests | `docker login`, potem `./start.sh` |
