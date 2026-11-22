# Sentinel ASI: pełny opis systemu

Dokument opisuje każdy ekran konsoli, każdy mechanizm i każde narzędzie po kolei: co robi,
skąd bierze dane, kto może z niego korzystać i gdzie jest w kodzie. Odpowiada na zadanie
HackNation „Attack Surface Intelligence” (CBI AGH, treść w [BRIEF.md](BRIEF.md)); stan
spełnienia wymagań jest w [REQUIREMENTS.md](REQUIREMENTS.md), instrukcja uruchomienia i
testu w [TESTOWANIE.md](TESTOWANIE.md).

Spis treści:

1. [Czym jest Sentinel ASI](#1-czym-jest-sentinel-asi)
2. [Architektura i usługi](#2-architektura-i-usługi)
3. [Droga skanu od celu do raportu](#3-droga-skanu-od-celu-do-raportu)
4. [Ekrany konsoli po kolei](#4-ekrany-konsoli-po-kolei)
5. [Mechanizmy discovery w szczegółach](#5-mechanizmy-discovery-w-szczegółach)
6. [Sentek: techniczny asystent](#6-sentek-techniczny-asystent)
7. [Bezpieczeństwo skanera i danych](#7-bezpieczeństwo-skanera-i-danych)
8. [Import, eksport, raporty, DefectDojo](#8-import-eksport-raporty-defectdojo)
9. [API discovery](#9-api-discovery)
10. [Konfiguracja](#10-konfiguracja)
11. [Kryteria testu z briefu i gdzie je sprawdzić](#11-kryteria-testu-z-briefu-i-gdzie-je-sprawdzić)
12. [Wydajność i wybór języka](#12-wydajność-i-wybór-języka)

---

## 1. Czym jest Sentinel ASI

Sentinel ASI to system do inwentaryzacji powierzchni ataku dużej sieci organizacji. Odkrywa
aktywne hosty w zakresach liczących dziesiątki tysięcy adresów, rozpoznaje usługi i
technologie WWW, wskazuje rzeczy ciekawe dla analityka (panele, środowiska testowe, ciekawe
nagłówki i ciasteczka, słabe certyfikaty), porównuje kolejne skany i śledzi hosty, które
pojawiają się i znikają. Wyniki są zaszyfrowane w bazie, można je poprawiać ręcznie,
eksportować i wysyłać do DefectDojo.

Zasady, których system pilnuje w kodzie, a nie tylko w dokumentacji:

- każde działanie sieciowe przechodzi przez `scope_guard` (zatwierdzony zakres, limity tempa),
- brak aktywnej eksploatacji: tylko wykrywanie hostów, rozpoznanie usług i pojedyncze GET,
- uprawnienia sprawdza backend na każdym endpoincie (deny-by-default), konsola wymaga MFA,
- każda akcja ludzi, harmonogramu i agenta trafia do dziennika audytu,
- poświadczenia tylko just-in-time z OpenBao, nigdy w bazie, logach, API ani kontekście modelu,
- zewnętrzny model językowy jest domyślnie wyłączony; Sentek odpowiada z danych i z wiedzy
  zapisanej w kodzie.

Moduł podatności (CVE, KEV, EPSS, skany L1–L3, agent AI) jest dodatkiem ponad brief. W menu
ma osobną grupę „Podatności (moduł dodatkowy)”, a discovery dużych sieci jest w grupie
„Discovery”.

## 2. Architektura i usługi

Wszystko startuje jednym poleceniem (`./start.sh`, na Windows `.\start.cmd`) w Docker
Compose. Usługi:

| Usługa | Rola |
|---|---|
| `frontend` | Konsola React (Vite, Tailwind) pod `/admin/`, serwowana przez nginx z proxy do API |
| `api` | FastAPI: REST, RBAC, audyt, szyfrowanie pól, walidacja celów |
| `worker-scans` | Celery: przebiegi discovery (nmap, fingerprint HTTP/TLS), skany L1 |
| `beat` | Zegar Celery: co minutę harmonogram discovery, cykliczne feedy |
| `worker-core`, `worker-feeds` | Dopasowanie oprogramowania do CVE, synchronizacja NVD/KEV/EPSS |
| `worker-llm`, `ollama` | Lokalny model (profil `llm`, opcjonalny): warstwa „W skrócie” raportów |
| `worker-agent`, `mcp-scanner`, `worker-harness` | Agent AI z planem zatwierdzanym przez człowieka, narzędzia przez MCP i scope_guard |
| `db` (PostgreSQL 16), `redis` | Baza (pola wyników zaszyfrowane) i kolejka zadań |
| `keycloak` | Logowanie OIDC z TOTP; role z `rules/roles.yaml` |
| `openbao`, `bao-init` | Sejf poświadczeń just-in-time |
| `mailpit` | Lokalna skrzynka do powiadomień e-mail |
| `lab-web`, `lab-proxy`, `lab-legacy` | Izolowana sieć demo `172.30.99.0/24` do pokazu skanu |
| DefectDojo (osobny compose) | Lokalna instancja pod <http://localhost:8081>, zakładana przez `scripts/bootstrap_defectdojo.sh` |

Kod: backend w `backend/app` (moduły `api`, `discovery`, `scanners`, `assistant`, `iam`,
`core`), reguły w `rules/*.yaml`, konsola w `frontend/admin` i `frontend/shared`, migracje w
`backend/alembic/versions`.

## 3. Droga skanu od celu do raportu

```
cele (ręcznie / plik CSV, JSON, TXT / harmonogram)
  → walidacja składni i limitu adresów            (parse_targets)
  → „Sprawdź cele”: decyzja scope_guard na cel     (POST /targets/preview)
  → przebieg w kolejce (queued)                    (new_run, audyt discovery_requested)
  → sweep: paczki CIDR, nmap -sn                   (każda paczka: scope_guard, czas, wynik)
  → ponowna próba /32 dla hostów widzianych wcześniej, a teraz cichych
  → skan usług aktywnych hostów, nmap -sV          (każdy host: scope_guard)
  → fingerprint HTTP/HTTPS + TLS + sygnatury       (tylko GET, ścieżki z sygnatur)
  → flagi: panel, staging, nagłówki, ciasteczka, brak nagłówków bezpieczeństwa
  → zapis obserwacji (pola zaszyfrowane)
  → koniec: done / stopped / paused (koniec okna: zapis reszty celów)
  → stany hostów, porównanie z poprzednim, raport, eksport, DefectDojo
```

## 4. Ekrany konsoli po kolei

Konsola: <http://localhost:8080/admin/>. Wejście wymaga zalogowania z TOTP. Menu pokazuje
tylko to, do czego rola ma uprawnienia; backend i tak sprawdza każde żądanie.

### 4.1 Pulpit (`/`)

Kafelki kluczowych wskaźników (aktywne zagrożenia, katalog CISA KEV, zasoby w inwentarzu,
sprawy do decyzji), karta „Ostatnie przebiegi discovery” ze statusem i liczbą hostów, „Wymaga
uwagi” (sprawy do decyzji człowieka), „Najważniejsze zagrożenia”, ostatnie powiadomienia i
aktywność z audytu oraz „Stan systemu” (feedy, kolejki, baza). Status „Wstrzymany” oznacza
przebieg, który doszedł do końca okna i czeka na wznowienie.

### 4.2 Raporty (`/raporty`)

Raporty okresowe modułu podatności, w dwóch warstwach: „W skrócie” dla kierownictwa i
szczegóły techniczne dla zespołu IT. Raport z pojedynczego przebiegu discovery jest na
stronie przebiegu (punkt 4.4 i rozdział 8).

### 4.3 Przebiegi discovery (`/discovery`)

**Nowy przebieg.** Pole „Cele”: adresy IPv4/IPv6, zakresy CIDR i domeny, po jednym w
wierszu, albo plik CSV, JSON lub TXT („Wczytaj cele z pliku”). Pola:

- „Nazwa przebiegu”,
- „Zakończ najpóźniej (opcjonalnie)”: po tej chwili skan kończy rozpoczęte paczki, zapisuje
  resztę celów i czeka na „Wznów”,
- „Równoległe workery” (procesy nmap naraz, limit z `rules/discovery.yaml`),
- „Pakiety na sekundę” (`--max-rate` na proces),
- „Szablon czasowy nmap” (0–3; T4 i T5 są zablokowane).

„Sprawdź cele” pokazuje dla każdego celu liczbę adresów, decyzję scope_guard i powód; dopiero
wtedy „Uruchom skan” staje się aktywne. Wymaga `scan:run`.

**Import wyników.** Wgranie gotowych wyników (JSON, CSV, nmap XML) jako przebieg typu import;
dalej działa porównanie, stany i eksport jak dla skanu. Wymaga `inventory:write`.

**Przebiegi.** Lista z postępem, statusem, liczbą hostów i czasem; link do strony przebiegu.

### 4.4 Strona przebiegu (`/discovery/:id`)

- **Statystyki**: status, liczba adresów, aktywne hosty, czas, ETA; pasek postępu z
  ustawieniami (workery, tempo, `-T`).
- **Panel wstrzymania** (status „Wstrzymany”): kiedy był koniec, ile adresów zostało (ile
  zakresów i ilu hostów bez skanu usług), przycisk „Wznów” z opcjonalnym nowym końcem. Gdy
  przebieg należy do harmonogramu cyklicznego, wznowi się sam w kolejnym oknie.
- **Ponowna próba**: informacja, ilu cichych hostów z poprzedniego przebiegu sprawdzono
  ponownie i ile odpowiedziało.
- **Paczki**: każda paczka sweepu i skanu usług z rozmiarem, czasem, liczbą hostów i
  wynikiem decyzji scope_guard. Rozmiar kolejnej paczki dobiera silnik.
- **Grupy podobnych usług**: te same port, usługa, produkt i wersja zebrane razem, z listą
  hostów (np. „5672/tcp amqp · RabbitMQ 3.12” na 4 hostach).
- **Hosty**: tabela z flagami, stanem (aktywny, niestabilny, niepotwierdzony, nieaktywny,
  z etykietą pory dnia), tagami i krytycznością; filtr po tagu. Kliknięcie adresu otwiera
  **kartę hosta**: usługi z wersjami, fingerprint HTTP (status, tytuł, nagłówki, ciasteczka,
  przekierowania, TLS, hash favicony, technologie, kody ścieżek, trafione sygnatury), flagi z
  dowodami i pewnością, historia odpowiedzi.
- **Edycja** (`findings:update`): nazwa hosta, notatka, tagi (po przecinku), ukryte flagi,
  krytyczność, status. Poprawki są zapisane osobno od wyników skanu, więc przeżywają kolejne
  skany i trafiają do audytu.
- **Eksport**: JSON, CSV, nmap XML. **Raport**: HTML, JSON, CSV (rozdział 8).
- **DefectDojo**: zaznaczone hosty wysyłane jako findings informacyjne (`defectdojo:export`).

### 4.5 Porównanie i stany (`/discovery/porownanie`)

Wykres „Zmiany w czasie”: liczba aktywnych hostów i usług w kolejnych przebiegach (słupki z
podpowiedzią). Wybór dwóch przebiegów pokazuje: nowe hosty, zniknięte hosty, zmienione hosty
(dodane, usunięte i zmienione usługi, technologie, nagłówki, tytuły, flagi, zmiana nazwy).
Eksport różnic do JSON i CSV. Stany hostów z historią ✓/✗ z ostatnich przebiegów.

### 4.6 Harmonogram (`/discovery/harmonogram`)

Dwa tryby:

- **Cyklicznie, w oknie czasowym**: częstotliwość (co godzinę … co tydzień), okno „od–do”
  (koniec wcześniejszy niż początek oznacza okno przez północ, np. 22:00–06:00), dni
  rozpoczęcia okna, strefa czasowa. Przebieg startuje tylko w oknie; jeśli nie zdąży, zapisuje
  resztę i wznawia ją w kolejnym oknie.
- **Jednorazowo**: dokładna data i godzina startu oraz końca. Przebieg rusza o starcie; jeśli
  nie skończy przed końcem, zapisuje stan i czeka na „Wznów”.

Tabela pokazuje następny start („wznowienie …”, „czeka na Wznów”, „wykonany”), trwające okno
i ostatni przebieg ze statusem. Dodawanie i zmiana wymagają `scan:run`, podgląd `scan:read`.

### 4.7 Sygnatury detekcyjne (`/discovery/sygnatury`)

Wbudowane sygnatury z `rules/signatures.yaml` (tylko odczyt) i własne, dodawane w konsoli.
Sygnatura to YAML opisujący wyłącznie, czego szukać w odpowiedzi GET:

```yaml
id: grafana-login
name: Grafana – logowanie
kind: panel                     # technology | panel | staging
match:
  - {type: title, pattern: "grafana"}
  - {type: cookie, pattern: "^grafana_session$"}
  - {type: path, path: /login, status: [200], pattern: "grafana"}
```

Typy dopasowań: `header`, `cookie`, `favicon_hash`, `html`, `title`, `generator`, `path`.
Walidator odrzuca każde nieznane pole (nie da się dopisać metody, treści żądania, poświadczeń
ani parametrów), a ścieżek wszystkich sygnatur razem może być najwyżej 10.

- „Sprawdź” waliduje bez zapisu, „Zapisz” zapisuje (audyt `signature_saved`).
- **„Inspekcja”** (przy każdej sygnaturze, wbudowanej i własnej) rozkłada sygnaturę na reguły
  opisane po ludzku („GET /wp-login.php zwraca 200, treść pasująca do …”), mówi, które reguły
  wymagają dodatkowego żądania przy skanie, ile usług z ostatniego przebiegu spełnia każdą
  regułę osobno, gdzie sygnatura trafiła (host, usługa, dowód) i ile hostów trafiała w
  ostatnich 10 przebiegach (z linkami do przebiegów). Pokazuje też pełną definicję.
- **„Testuj”** (przy każdej sygnaturze i „Testuj na przebiegu” w edytorze) dopasowuje
  sygnaturę do wyników zapisanych w wybranym przebiegu, **bez żadnego ruchu w sieci**:
  pokazuje, które hosty i usługi pasują, z dowodem, i czy sygnatura była już w wynikach.
  Nagłówki, ciasteczka, tytuł, hash favicony i kody ścieżek sprawdza od razu. Treści stron nie
  przechowujemy (minimalizacja danych), więc `html`, `generator` i wzorzec treści przy `path`
  sprawdzi dopiero kolejny skan; ekran mówi to wprost.

### 4.8 Moduł podatności: Zasoby, Zagrożenia, Feed, Kolejka weryfikacji

- **Zasoby** (`/zasoby`): inwentarz z historią, źródłem (skan, CSV, DNS, DHCP), atrybutami i
  zagrożeniami.
- **Zagrożenia** (`/zagrozenia`): zagrożenia przypisane do zasobów, z oceną ryzyka (CVSS, KEV,
  EPSS, ekspozycja, krytyczność), właścicielem, statusem i terminem naprawy.
- **Feed zagrożeń** (`/feed`): dzisiejsze podatności, z wyróżnieniem tych, które nas dotyczą.
- **Kolejka weryfikacji** (`/weryfikacja`): dopasowania oprogramowania do CVE o niskiej
  pewności, czekające na decyzję człowieka.

### 4.9 Kontrola

- **Skany podatności** (`/skany`): skany L1–L3 do dopasowania CVE; akcje L2 i L3 czekają na
  zgodę człowieka z odpowiednim uprawnieniem.
- **Zakres skanowania** (`/zakres`): dozwolone i wykluczone sieci i domeny, limity tempa, tryb
  demo, „Sprawdź cel” (decyzja scope_guard dla dowolnego adresu bez skanowania).
- **Agent AI** (`/agent`): zadania w języku naturalnym; agent układa plan, człowiek go
  zatwierdza, każde narzędzie idzie przez MCP i scope_guard; poświadczenia just-in-time.
- **Test agenta** (`/agent/test`): scenariusze sprawdzające, czy agent nie omija zasad.
- **Dziennik audytu** (`/audyt`): każda akcja ludzi, harmonogramu i agenta (kto, co, kiedy,
  dlaczego, z jakimi parametrami); filtr i eksport.
- **Role i użytkownicy** (`/role`): macierz uprawnień, edytor ról własnych, użytkownicy.
- **IAM** (`/iam`): zakładki Human i Non-human. Ludzie: role, dostęp do trzech warstw,
  delegacje (osoba × warstwa × podsieć × okno czasu). Non-human: agent AI ze zdolnościami,
  role i konta techniczne.
- **Trzy warstwy** (`/warstwy`, sekcja „Skanowanie podatności”): warstwa 1 to deterministyczny
  skan narzędziami red team (nmap z bezpiecznym NSE, nuclei bez tagów eksploatacji), warstwa 2
  to analiza jej logów modelem (domyślnie szablon reguł), warstwa 3 to agent AI. Każda
  uruchamiana osobno i jawnie; domyślnie tylko administrator. Szczegóły:
  [WARSTWY.md](WARSTWY.md).

### 4.10 Role

| Rola | Co może w discovery |
|---|---|
| administrator | wszystko, w tym zakres, role i integracje |
| editor | uruchamianie i zatrzymywanie przebiegów, harmonogram, sygnatury, import, edycja wyników, DefectDojo; warstwy red team i agent tylko z delegacji |
| modifier | edycja istniejących wyników (notatki, tagi, krytyczność, status), odczyt, eksport |
| viewer | odczyt, porównanie, raporty i eksport JSON/CSV, test sygnatur na zapisanych danych |

Pełna macierz rola × endpoint: [ROLES.md](ROLES.md) (generowana z kodu, sprawdzana testem).

## 5. Mechanizmy discovery w szczegółach

### 5.1 Walidacja celów i limit

`parse_targets` rozpoznaje IPv4, IPv6, CIDR i domeny, zgłasza błędy składni, liczy adresy.
Jeden przebieg obejmuje najwyżej `limits.addresses` (domyślnie 70 000 adresów, czyli /16 z
zapasem).

### 5.2 scope_guard

Każda paczka CIDR, każdy host, każda domena po rozwiązaniu (wszystkie adresy, IPv4 i IPv6),
ponowna próba /32 i każde żądanie fingerprintu dostaje osobną decyzję. Odmowa jest w
paczkach przebiegu i w audycie. Typy `ScopedNetwork` i `ScopedTarget` może wytworzyć tylko
scope_guard, a adapter nmap przyjmuje wyłącznie te typy, więc nie ma ścieżki, która go omija.

### 5.3 Sweep w paczkach adaptacyjnych

Zakres dzielony jest na paczki CIDR. Pierwsza ma `batch_initial` adresów (256), kolejne
rosną albo maleją w granicach 16–1024 tak, żeby paczka trwała około `batch_target_seconds`
(20 s). Równolegle działa `workers` procesów nmap, każdy z `--max-rate`. Postęp i ETA liczą
się z mierzonej szybkości. Polecenie:

```
nmap -sn -n -PE -PS<porty wykrywania> -T3 --max-rate <tempo> -oX - <paczka>
```

`-PE` to ICMP echo, `-PS` to TCP SYN na porty typowe dla usług wewnętrznych, więc hosty z
zablokowanym ICMP i tak odpowiadają.

### 5.4 Ponowna próba dla hostów niestabilnych

Adresy, które odpowiadały w poprzednim przebiegu tego samego zakresu, a teraz milczą, dostają
drugą, pojedynczą próbę (/32 albo /128) w tym samym przebiegu (`retry_missing`, najwyżej
`retry_limit` = 256 hostów). Podsumowanie mówi, ilu sprawdzono i ilu odpowiedziało.

### 5.5 Skan usług

Każdy aktywny host: `nmap -sV -Pn -n -T3 --max-rate <tempo> -p <porty usług> --open`.
Wynik: port, protokół, usługa, produkt, wersja.

### 5.6 Fingerprint HTTP/HTTPS i TLS

Dla usług WWW: jedno GET na stronę główną (z przekierowaniami) i GET na ścieżki z sygnatur.
Zapisujemy status, tytuł, nagłówki (skrócone), ciasteczka (nazwa, Secure, HttpOnly),
przekierowania, hash favicony (MurmurHash3, jak w Shodan), technologie, kody ścieżek i
trafione sygnatury. Dla HTTPS dane certyfikatu: podmiot, wystawca, daty, SAN, samopodpisany.
Treści stron nie zapisujemy.

### 5.7 Flagi

| Flaga | Kiedy |
|---|---|
| Panel administracyjny lub logowania | tytuł (admin, login, panel, dashboard, phpMyAdmin…), formularz z hasłem, `/admin` lub `/login` odpowiada, przekierowanie do logowania, sygnatura `kind: panel` |
| Środowisko testowe / staging | nazwa hosta lub SAN (staging, test, dev, uat, qa, preprod, demo), tytuł, sygnatura `kind: staging` |
| Ciekawe nagłówki | `server`, `x-powered-by`, `x-aspnet-version`, `x-debug-token`, `x-backend-server`, `x-jenkins`, CORS |
| Ciekawe ciasteczka | nazwy z debug/admin/test/role, ciasteczko sesji bez Secure/HttpOnly |
| Brak nagłówków bezpieczeństwa (HTTPS) | brak HSTS, CSP albo X-Frame-Options |

Każda flaga ma dowody i pewność (niska, średnia, wysoka, zależnie od liczby dowodów).
Fałszywy alarm można ukryć na karcie hosta (ukryte flagi), bez kasowania wyniku skanu.

### 5.8 Stany hostów i pora dnia

Stan liczony z ostatnich przebiegów, które obejmowały adres (okno 5 przebiegów):

- **aktywny**: odpowiedział ostatnio i nie ma przeplotu odpowiedzi,
- **niestabilny**: odpowiedzi przeplatają się z ich brakiem (co najmniej dwie zmiany w oknie),
- **niepotwierdzony**: nie odpowiedział ostatnio, ale braków jest mniej niż 3,
- **nieaktywny**: 3 kolejne przebiegi bez odpowiedzi.

Przebieg wstrzymany na końcu okna nie liczy się jako brak odpowiedzi (nie objął całego
zakresu). Etykieta pory dnia porównuje odpowiedzi w dzień (7–19) i w nocy: „tylko w dzień”
albo „tylko w nocy” wskazuje np. stacje robocze wyłączane na noc.

### 5.9 Harmonogram, koniec skanu i wznowienie

Beat co 60 sekund wywołuje `tick`: dla każdego włączonego harmonogramu sprawdza, czy trwa jego
przebieg, czy jest okno i czy minęła częstotliwość (dla jednorazowego: czy nadeszła godzina
startu). Przebieg dostaje `deadline` = koniec okna. Silnik przed każdą paczką sprawdza termin:
po nim kończy rozpoczęte paczki, zapisuje niezeskanowane sieci i aktywne hosty bez skanu usług
w `remaining` i ustawia status „Wstrzymany”. Cykliczny harmonogram wznawia resztę w kolejnym
oknie; jednorazowy i zwykły przebieg z godziną końca wznawia człowiek („Wznów”, endpoint
`POST /runs/{id}/resume`, audyt). Wznowienie to nowy przebieg z odnośnikiem do poprzedniego;
drugi raz tego samego przebiegu wznowić się nie da.

### 5.10 Ocena ciekawości (priorytet analityczny)

W raporcie z przebiegu każdy host dostaje punkty z jawnymi wagami: panel 3, staging 3, TLS 2,
ciekawe nagłówki 1, ciekawe ciasteczka 1, brak nagłówków bezpieczeństwa 1, stan niestabilny
lub niepotwierdzony 1, krytyczność wysoka 2 albo krytyczna 3, nowy host od poprzedniego
przebiegu 2. Lista jest posortowana i każda pozycja mówi, za co dostała punkty.

### 5.11 Ręczne poprawki

Nazwa hosta, notatka, tagi (małe litery, bez powtórzeń, do 20 po 40 znaków), ukryte flagi,
krytyczność i status są zapisane jako nadpisania per adres IP (zaszyfrowane), łączone z
wynikami przy odczycie. Kolejny skan ich nie kasuje, a każda zmiana jest w audycie.

## 6. Sentek: techniczny asystent

Sentek (prawy dolny róg konsoli) odpowiada tylko na pytania techniczne o skanowanie i wyniki.
Niczego nie uruchamia i nie zmienia; odpowiedzi buduje kod z danych w bazie (w granicach
uprawnień pytającego) albo z wiedzy technicznej zapisanej w kodzie
(`backend/app/assistant/knowledge.py`, wartości domyślne i limity czytane z
`rules/discovery.yaml`). Pytania spoza tematu dostają odmowę z listą tematów.

| Rodzaj pytania | Przykład | Skąd odpowiedź |
|---|---|---|
| Typowe skany i ustawienia | „Jak ustawić skan sieci /16 w nocy?” | wiedza + limity z konfiguracji |
| Flagi nmap | „Jakie flagi nmap uruchamia Sentinel?” | dokładne polecenia silnika |
| Porty i usługi | „Do czego służy port 5672?” | tabela typowych portów z uwagami |
| Diagnostyka | „Dlaczego host nie pojawia się w wynikach?” | lista przyczyn i co sprawdzić |
| Tempo | „Co zrobić, gdy skan trwa za długo?” | jak dobrać workery, tempo, porty |
| Sygnatury | „Jak napisać własną sygnaturę?” | przykład YAML i test |
| Harmonogram | „Jak działa skan jednorazowy i wznowienie?” | opis trybów i zapisu stanu |
| Zakres | „Dlaczego cel jest poza zakresem?” | zasady scope_guard, IPv6 w Dockerze |
| Eksport | „W jakich formatach pobiorę wyniki?” | formaty eksportu i raportu |
| Zmiany | „Co się zmieniło od ostatniego skanu?” | porównanie dwóch ostatnich przebiegów |
| Hosty niestabilne | „Które hosty są niestabilne?” | stany z historią ✓/✗ |
| Flagi WWW | „Gdzie są panele administracyjne?” | flagi z fingerprintu |
| TLS | „Czy jakieś certyfikaty wygasają?” | certyfikaty z fingerprintu |
| Technologie | „Jakie technologie wykryto?” | technologie z fingerprintu |
| Porty na hostach | „Pokaż urządzenia z otwartym portem 80” | wyniki skanu |
| Ryzyko (moduł CVE) | „Podsumuj krytyczne zagrożenia” | zagrożenia, KEV, terminy |
| DefectDojo, dostęp | „Czy DefectDojo działa?”, „Jakie mam uprawnienia?” | baza, rola |

Prośba o zmianę („usuń”, „wyłącz”, „dodaj do zakresu”) dostaje odmowę; prośba o skan zamienia
się w propozycję zadania, które człowiek zleca i zatwierdza. Każde pytanie jest w audycie jako
rozpoznana intencja, bez treści pytania.

## 7. Bezpieczeństwo skanera i danych

Skaner:

- tylko `-sn`, `-sV` i GET; brak skanów UDP, skryptów NSE, prób logowania, POST i fuzzingu,
- `-T` najwyżej 3, `--max-rate` i liczba workerów z limitami w `rules/discovery.yaml`,
- scope_guard na każdym kroku, deny wygrywa z allow, limity tempa per cel,
- „Zatrzymaj” kończy rozpoczęte paczki i nie startuje nowych.

Dane:

- szyfrowanie w spoczynku (Fernet: AES-128-CBC + HMAC-SHA256) pól z wynikami skanów, celami
  harmonogramów i resztą wstrzymanych przebiegów; klucz `DATA_ENCRYPTION_KEY` tylko w `.env`,
  rotacja kluczem poprzednim: [DATA_PROTECTION.md](DATA_PROTECTION.md),
- RBAC na każdym endpoincie, MFA do konsoli, audyt każdej akcji,
- w repozytorium tylko fikcyjne dane demo i syntetyczne fixture'y.

## 8. Import, eksport, raporty, DefectDojo

**Import** (Discovery → Import wyników): JSON (`[{ip, hostname, services[], http[]}]` albo
`{"hosts": [...]}`), CSV (kolumna `ip`, opcjonalnie `hostname, port, protocol, service,
product, version`), nmap XML (`-oX`).

**Eksport przebiegu**: JSON (przebieg i pełne dane hostów), CSV (kolumny `ip, hostname, port,
protocol, service, product, version, title, technologies, flags`), nmap XML.

**Eksport porównania**: JSON i CSV z nowymi, zniknętymi i zmienionymi hostami i usługami.

**Raport z przebiegu** (`GET /runs/{id}/report?format=html|json|csv`):

| Sekcja | Zawartość |
|---|---|
| Podsumowanie | hosty, usługi, usługi WWW, technologie, flagi wg rodzaju, stany, ile hostów poprawiono ręcznie |
| Najważniejsze zmiany | porównanie z poprzednim przebiegiem: nowe, zniknięte, zmienione hosty i usługi |
| Priorytet analityczny | ocena ciekawości z wagami i uzasadnieniem |
| Flagi | każda flaga z dowodami i pewnością |
| Certyfikaty TLS | wygasłe, wygasające w 30 dni, samopodpisane |
| Stany | hosty niestabilne, niepotwierdzone i nieaktywne z historią i porą dnia |
| Grupy usług | port, usługa, produkt, wersja i lista hostów |
| Technologie | technologia i liczba hostów |

JSON i CSV to formaty eksportu wymagane w briefie; HTML jest do czytania i druku (w
przeglądarce „Drukuj → Zapisz jako PDF”). CSV ma kolumny `section, ip, hostname, port, item,
detail`, a komórki zaczynające się od `=`, `+`, `-`, `@` są neutralizowane (ochrona przed
formułami w arkuszu).

**DefectDojo**: zaznaczone hosty idą jako findings informacyjne do Engagement „Sprint final” →
Test „Discovery” w lokalnym DefectDojo (<http://localhost:8081>, `admin`, hasło
`DD_ADMIN_PASSWORD` z `.env`). Do DefectDojo nie trafiają logi aplikacji, tylko wybrane
obserwacje.

## 9. API discovery

Wszystkie ścieżki pod `/api/discovery`. Uprawnienie sprawdza backend; macierz ról w
[ROLES.md](ROLES.md).

| Metoda i ścieżka | Uprawnienie | Co robi |
|---|---|---|
| `GET /settings` | `scan:read` | wartości domyślne i limity |
| `POST /targets/preview` | `scan:read` | walidacja celów i decyzja scope_guard (bez skanu) |
| `POST /runs` | `scan:run` | nowy przebieg (opcjonalnie `end_at`) |
| `GET /runs`, `GET /runs/{id}` | `scan:read` | lista, szczegóły z paczkami, reszta do wznowienia |
| `POST /runs/{id}/stop` | `scan:run` | zatrzymanie |
| `POST /runs/{id}/resume` | `scan:run` | wznowienie wstrzymanego przebiegu (opcjonalnie nowy `end_at`) |
| `GET /runs/{id}/hosts` | `scan:read` | hosty z poprawkami i stanami |
| `GET /runs/{id}/export` | `reports:export` | eksport JSON, CSV, nmap XML |
| `GET /runs/{id}/report` | `reports:export` | raport HTML, JSON, CSV |
| `GET /compare`, `GET /compare/export` | `scan:read`, `reports:export` | różnice dwóch przebiegów |
| `GET /states` | `scan:read` | stany hostów |
| `PUT /overrides/{ip}` | `findings:update` | ręczna poprawka |
| `POST /import` | `inventory:write` | import wyników |
| `GET/POST/PUT/DELETE /schedules` | `scan:read` / `scan:run` | harmonogram cykliczny i jednorazowy |
| `GET /signatures` | `scan:read` | sygnatury wbudowane i własne |
| `POST /signatures/check`, `PUT`, `DELETE /signatures/{id}` | `scan:run` | walidacja, zapis, usunięcie |
| `POST /signatures/test` | `scan:read` | test sygnatury na zapisanym przebiegu, bez sieci |
| `GET /signatures/{id}/inspect` | `scan:read` | inspekcja: reguły, trafienia reguła po regule, historia, dowody |
| `GET /defectdojo/status`, `POST /defectdojo/export` | `scan:read`, `defectdojo:export` | stan i wysyłka do DefectDojo |

## 10. Konfiguracja

| Plik | Zawartość |
|---|---|
| `rules/discovery.yaml` | domyślne workery, tempo, `-T`, paczki, porty wykrywania i usług, ścieżki HTTP; limity; progi stanów hostów |
| `rules/signatures.yaml` | wbudowane sygnatury |
| `rules/scope*.yaml` | zatwierdzony zakres (allow/deny), limity tempa |
| `rules/roles.yaml` | uprawnienia i role |
| `.env` | hasła, `DATA_ENCRYPTION_KEY`, `DATA_ENCRYPTION_KEYS_OLD`, dane DefectDojo; tworzony przez `scripts/ensure_env.sh`, poza Gitem |

## 11. Kryteria testu z briefu i gdzie je sprawdzić

| Kryterium (brief, sekcja 6) | Gdzie |
|---|---|
| 1. Wykrycie aktywnych hostów | Przebieg → Hosty; mechanizm 5.3–5.4 |
| 2. Identyfikacja usług | karta hosta, Grupy podobnych usług; 5.5 |
| 3. Fingerprint HTTP/HTTPS | karta hosta (fingerprint, TLS); 5.6 |
| 4. CMS-y i technologie | kolumna technologii, sygnatury `technology`, raport → Technologie |
| 5. Ciekawe nagłówki i ciasteczka | flagi; 5.7 |
| 6. Customowe sygnatury | Sygnatury: dodanie, „Testuj”, „Inspekcja”, trafienia w kolejnym przebiegu; 4.7 |
| 7. Porównanie skanów | Porównanie i stany, raport → Najważniejsze zmiany |
| 8. Hosty niestabilne | stany i pora dnia, ponowna próba /32; 5.4, 5.8 |
| 9. Bezpieczeństwo i ostrożność | rozdział 7, Zakres, Dziennik audytu |
| 10. Czytelność dashboardu i raportu | Pulpit, raport HTML |
| 11. Import i eksport | Import wyników, eksport JSON/CSV/XML, raport; rozdział 8 |
| 12. Role | Role i użytkownicy, [ROLES.md](ROLES.md); 4.10 |

## 12. Wydajność i wybór języka

Wyniki pomiarów: [PERFORMANCE.md](PERFORMANCE.md). Brief sugeruje języki o niskim zużyciu
zasobów (Go, Rust, C++). Skanowanie w Sentinelu wykonuje nmap, napisany w C/C++; Python
tylko dzieli zakres na paczki, pilnuje zakresu i zapisuje wyniki. Pomiar pokazuje, że czas
przebiegu zależy od sieci i nmapa, a proces Pythona zużywa niewielki ułamek CPU, więc
przepisanie orkiestracji na C++ nie skróciłoby skanu, a zepsułoby działający, przetestowany
system. Tempo zwiększa się workerami i `--max-rate` w granicach limitów.
