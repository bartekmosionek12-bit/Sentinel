# Test na laboratorium od mentorów (lab.zip)

Stan na 2026-11-22, gałąź `sprint-final`. Laboratorium to syntetyczne środowisko
organizatorów (kontenery Dockera na własnym komputerze), więc w repo nie ma tu żadnych
danych o prawdziwej infrastrukturze.

Test uruchamia prawdziwy silnik discovery (nmap + fingerprint HTTP + własne sygnatury)
z domyślną konfiguracją z `rules/discovery.yaml` i `rules/signatures.yaml`. Zakres
skanowania to dokładnie podane cele; każde działanie sieciowe przechodzi przez `scope_guard`.

## Wyniki

| Stack z lab.zip | Cel | Wynik |
|---|---|---|
| quickstart (3 przebiegi: start, `change`, `up`) | `127.0.0.1` | 5/5 portów (2223, 3001, 5673, 8787, 15673). Przebieg 2: zmieniony host, znikająca usługa 8787/nginx. Przebieg 3: usługa 8787 wraca. Gitea (strona instalacji jako panel), RabbitMQ 3.13.7 i panel RabbitMQ Management rozpoznane. |
| custom-network (całość) | `127.0.0.1` | 7/7: dodatkowo httpbin (8888) i PostgreSQL na 15432. |
| vulnerable | `127.0.0.1` i sieć Dockera /24 | WordPress 4.7 (strona instalacji), DVWA (panel logowania, staging z tytułu „Development”), vsftpd 3.0.2, MySQL 5.7.44. Adminer nie startuje w środowisku bez IPv6 (błąd obrazu, nie skanera). |
| modern | `127.0.0.1` | WordPress, phpMyAdmin (panel), Redis 7.4, Nginx Proxy Manager (panel na 81, OpenResty). NPM w środowisku bez IPv6 wymaga `DISABLE_IPV6=true`. |
| modern-proxy | – | Obraz Toxiproxy z ghcr.io był niedostępny w środowisku testowym. Sam dashboard Traefika (obraz z tego stacku) rozpoznany, z przekierowaniem `/` → `/dashboard/`. |

Przebieg na `127.0.0.1` trwa ok. 105 s, gdy działa Gitea albo RabbitMQ (`nmap -sV` długo
sprawdza nierozpoznane usługi), a ok. 7–12 s bez nich.

## Co poprawiliśmy po pierwszym teście

1. **Przekierowania na porcie 80/443.** httpx usuwa z adresu port domyślny, więc tekstowe
   porównanie z `http://host:80` przerywało śledzenie przekierowań. Teraz porównujemy
   schemat, host i port. Skutek: WordPress i DVWA rozpoznane (wcześniej pusty tytuł).
2. **Porty labu i typowe porty usług wewnętrznych** w `rules/discovery.yaml`.
3. **Fingerprint na nietypowych portach WWW** (np. Gitea na 3001, którą nmap nazywa „nessus”).
4. **Własne sygnatury detekcyjne** (wymaganie z briefu) w `rules/signatures.yaml`, z
   walidatorem: tylko typy dopasowań z briefu (nagłówek, ciasteczko, hash favicony, fragment
   HTML, tytuł, meta generator, ścieżka GET bez logowania), żadnych metod, treści żądań ani
   poświadczeń, najwyżej 10 dodatkowych ścieżek. Ścieżka może wymagać fragmentu treści, bo
   aplikacje SPA (np. Nginx Proxy Manager) odpowiadają 200 na każdą ścieżkę.

## Znane ograniczenia

- Aplikacja w Dockerze nie widzi `localhost` komputera. W UI skanujemy wtedy adres bramy
  sieci Dockera (np. `172.17.0.1`) albo sieć labu, i ten adres musi być w `rules/scope.yaml`.
  `scope.demo.yaml` celowo blokuje bramę. Skrypt z tej instrukcji działa na hoście, więc
  skanuje `127.0.0.1` bezpośrednio.
- Po `./quickstart.sh up` RabbitMQ potrzebuje ok. 30 s; skan wcześniej pokaże porty
  5673 i 15673 jako `tcpwrapped` bez panelu.

## Jak odtworzyć testy

### 1. Testy automatyczne (bez Dockera)

```bash
cd backend
uv sync
uv run ruff check .
uv run mypy app
uv run pytest                      # cały backend
uv run pytest tests/test_signatures.py tests/test_discovery.py   # tylko discovery i sygnatury

cd ../frontend
npm ci
npx tsc --noEmit -p .
npx playwright test --trace off   # e2e na atrapach API
```

### 2. Lab od mentorów (Linux, macOS albo WSL na Windowsie)

Potrzebne: Docker, `nmap`, `uv`. Skrypt działa na hoście (nie w kontenerze), bo lab
publikuje porty na `localhost`.

```bash
# lab.zip od mentorów rozpakowany np. do ~/lab
cd ~/lab && ./quickstart.sh up && sleep 30

cd /ścieżka/do/Sentinel/backend && uv sync
uv run python ../scripts/lab_scan.py /tmp/lab.sqlite przebieg-1 127.0.0.1

cd ~/lab && ./quickstart.sh change
cd /ścieżka/do/Sentinel/backend
uv run python ../scripts/lab_scan.py /tmp/lab.sqlite przebieg-2 127.0.0.1 --compare
#   oczekiwane: zmieniony 127.0.0.1, usługa 8787/tcp w „removed”

cd ~/lab && ./quickstart.sh up && sleep 30
cd /ścieżka/do/Sentinel/backend
uv run python ../scripts/lab_scan.py /tmp/lab.sqlite przebieg-3 127.0.0.1 --compare
#   oczekiwane: usługa 8787/tcp w „added”

cd ~/lab && ./quickstart.sh down
```

Pozostałe stacki: `docker compose -f docker-compose-vulnerable.yml up -d` (albo
`-modern.yml`, `-custom-network.yml`), potem ten sam skrypt na `127.0.0.1` z nową bazą,
na koniec `docker compose -f … down`. Uruchamiaj jeden stack naraz (porty się pokrywają).
Sieć Dockera danego stacku też da się skanować: `docker network inspect <sieć>` poda
podsieć, a jako cel podaj jej /24, np. `172.20.0.0/24`.

### 3. To samo w aplikacji

Po `.\start.cmd` (albo `./start.sh`): konsola → Discovery → wpisz cel w formularzu
(adres bramy Dockera albo podsieć labu, jeśli są w zakresie) → Uruchom skan. Po trzech
przebiegach: Discovery → Porównanie i stany.
