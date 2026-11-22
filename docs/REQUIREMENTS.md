# Macierz zgodności z briefem AGH

Stan na 22.11.2026 (po sprincie końcowym). Źródło wymagań: [BRIEF.md](BRIEF.md). Jak to
sprawdzić krok po kroku: [TESTOWANIE.md](TESTOWANIE.md).

**Status:** ✅ jest · 🟡 częściowo · ❌ brak.

**Kryteria oceny (sekcja 8 briefu):** K1 discovery 30% · K2 jakość, dokumentacja, import i
eksport, DefectDojo 20% · K3 zmiany w czasie i hosty niestabilne 15% · K4 bezpieczeństwo i
dashboard 15% · K5 fingerprinting i sygnatury 10% · K6 role i ochrona danych 10%.

## Podsumowanie

| Grupa | ✅ | 🟡 | ❌ |
|---|---|---|---|
| Sekcja 2, pkt 1–16 | 16 | 0 | 0 |
| Sygnatury i harmonogram (akapity sekcji 2) | 2 | 0 | 0 |
| Minimalny zakres (sekcja 3) | 14 | 0 | 0 |
| Mile widziany zakres (sekcja 3) | 10 | 1 | 0 |
| Walidacja (sekcja 6, pkt 1–12) | 12 | 0 | 0 |

Częściowo zostaje tylko N11 (źródła pasywne): podłączymy je, gdy organizator je udostępni.

## A. Sekcja 2, pkt 1–16

| ID | Wymaganie | Status | Gdzie |
|---|---|---|---|
| R1 | Lista IP, zakresów CIDR, domen | ✅ | Discovery → Przebiegi: formularz, plik CSV/JSON/TXT, podgląd z decyzją zakresu (`/api/discovery/targets/preview`) |
| R2 | Skan wielowątkowy, pomiar czasu, podgrupy dobierane do szybkości | ✅ | `discovery/engine.py`: paczki o rozmiarze z mierzonej szybkości (16–1024 adresów), równoległe workery nmap, czas paczki i przebiegu, ETA, zapis przyrostowy |
| R3 | Wykrycie aktywnych hostów | ✅ | `nmap -sn -PE -PS<40 portów>`, ponowna próba /32 dla hostów, które odpowiadały poprzednio |
| R4 | Identyfikacja usług | ✅ | `nmap -sV` tylko na aktywnych hostach, lab mentorów 5/5 usług |
| R5 | HTTP/HTTPS: tytuł, kod, nagłówki, ciasteczka, TLS, przekierowania | ✅ | `discovery/fingerprint.py` (też hash favicony mmh3, sprawdzone ścieżki GET) |
| R6 | Technologie, CMS-y | ✅ | Sygnatury wbudowane (`rules/signatures.yaml`) i własne, dowody przy każdej |
| R7 | Panel administracyjny, staging | ✅ | Flagi z dowodami i pewnością (nazwa, tytuł, ścieżki, przekierowania do logowania) |
| R8 | Porównanie przebiegów | ✅ | Discovery → Porównanie: dowolne dwa przebiegi, eksport JSON/CSV |
| R9 | Nowe, znikające, zmienione usługi | ✅ | `analysis.compare`: hosty, usługi, technologie, nagłówki, tytuły, flagi |
| R10 | Własne sygnatury | ✅ | Discovery → Sygnatury detekcyjne: YAML, walidator (tylko GET, bez treści i poświadczeń) |
| R11 | Formularz, CSV, JSON przetwarzane tak samo | ✅ | Jedna ścieżka `parse_targets` dla celów; import wyników JSON/CSV/nmap XML jak skan |
| R12 | RBAC z tworzeniem ról | ✅ | `rules/roles.yaml`, `require()` na każdym endpoincie, edytor ról, [ROLES.md](ROLES.md) |
| R13 | Cztery role z briefu | ✅ | `administrator`, `editor`, `modifier`, `viewer`, MFA w Keycloak |
| R14 | Edycja niezależna od skanu, zachowana w kolejnych | ✅ | Warstwa nadpisań (nazwa, krytyczność, status, notatka, tagi), audyt kto i kiedy |
| R15 | Czytelny interfejs, dashboard | ✅ | Pulpit z kluczowymi wskaźnikami, discovery, zmianami i stanem DefectDojo |
| R16 | Szyfrowanie w spoczynku pól wrażliwych | ✅ | [DATA_PROTECTION.md](DATA_PROTECTION.md), migracja 0017, rotacja kluczy |

## B. Akapity sekcji 2: sygnatury i harmonogram

| ID | Wymaganie | Status | Gdzie |
|---|---|---|---|
| S1 | Sygnatury bezpieczne (nagłówek, ciasteczko, favicon, HTML, ścieżka bez logowania, wersja, CMS) | ✅ | Typy `header`, `cookie`, `favicon_hash`, `html`, `title`, `generator`, `path`; najwyżej 10 ścieżek GET na usługę |
| S2 | Przedziały czasowe i częstotliwość; po przekroczeniu okna zatrzymanie i wznowienie w kolejnym | ✅ | Discovery → Harmonogram; `discovery/schedule.py`: okno (też przez północ), dni tygodnia, częstotliwość; na końcu okna stan „wstrzymany”, reszta celów zapisana (szyfrowana) i wznowiona w następnym oknie |

## C. Minimalny oczekiwany zakres (sekcja 3)

| ID | Wymaganie | Status | Gdzie |
|---|---|---|---|
| M1 | Import listy hostów lub zakresów | ✅ | R1 |
| M2 | Import wyników JSON lub CSV | ✅ | Discovery → Import wyników (JSON, CSV, nmap XML) |
| M3 | Ponad 10 000 IP | ✅ | Pomiar na prawdziwym nmapie, zakres /18: [PERFORMANCE.md](PERFORMANCE.md) |
| M4 | Okno czasowe i częstotliwość | ✅ | S2 |
| M5 | Ograniczanie tempa | ✅ | `--max-rate` na worker, liczba workerów, T3 jako maksimum, limit akcji na cel w scope_guard |
| M6 | Aktywne hosty | ✅ | R3 |
| M7 | Identyfikacja usług | ✅ | R4 |
| M8 | Zapis do bazy | ✅ | PostgreSQL, zapis po każdej paczce |
| M9 | Porównanie dwóch skanów | ✅ | R8 |
| M10 | Dashboard najważniejszych zmian | ✅ | Pulpit, Porównanie i stany, wykres zmian w czasie |
| M11 | Eksport JSON lub CSV | ✅ | Przebieg → JSON, CSV, nmap XML; różnice → JSON, CSV |
| M12 | Role | ✅ | R12, R13 |
| M13 | Edycja skanów, wyników i konfiguracji | ✅ | R14, edycja harmonogramów, sygnatur i ról |
| M14 | Szyfrowanie danych ze skanów | ✅ | R16 |

## D. Mile widziany zakres (sekcja 3)

| ID | Wymaganie | Status | Gdzie |
|---|---|---|---|
| N1 | Harmonogram cyklicznych skanów | ✅ | S2 |
| N2 | Różnice zależne od pory dnia | ✅ | Profil dzień (7–19) / noc na stan hosta: „odpowiada tylko w dzień / w nocy” |
| N3 | Ocena „ciekawości” | ✅ | Flagi z pewnością (wysoka, średnia, niska) i dowodami; sortowanie hostów po flagach |
| N4 | Powtarzanie pomiarów hostów niestabilnych | ✅ | Druga próba /32 w tym samym przebiegu; stany aktywny, niestabilny, niepotwierdzony, nieaktywny |
| N5 | Fingerprinting HTTP/HTTPS | ✅ | R5 |
| N6 | Wykrywanie CMS-ów i technologii | ✅ | R6 |
| N7 | Grupowanie podobnych usług | ✅ | Przebieg → „Grupy podobnych usług” (port, usługa, wersja, technologia) |
| N8 | Tagi | ✅ | Edycja na karcie hosta, filtr po tagu w przebiegu |
| N9 | Eksport do DefectDojo (finding Info) | ✅ | Przebieg → „Wyślij do DefectDojo”, lokalne DefectDojo przy każdym starcie, deduplikacja |
| N10 | Wizualizacja zmian w czasie | ✅ | Porównanie i stany → „Zmiany w czasie” (hosty, usługi na przebieg) |
| N11 | Źródła pasywne | 🟡 | Feedy NVD, KEV, EPSS; inne źródła po udostępnieniu przez organizatora |

## E. Wymagania formalne i techniczne (sekcje 4–5)

| ID | Wymaganie | Status | Uwagi |
|---|---|---|---|
| F1 | Repozytorium | ✅ | GitHub, CI |
| F2 | Dokumentacja techniczna | ✅ | [DOKUMENTACJA.md](DOKUMENTACJA.md) (punkt wejścia), szczegóły w OPIS_SYSTEMU, ROLES, WARSTWY, DATA_PROTECTION, PERFORMANCE, TESTOWANIE, LAB_TEST |
| F3 | Prezentacja do 10 slajdów | 🟡 | Slajdy przygotowane, slajd o skali czeka na ostateczny wynik pomiaru; scenariusz filmu demo: [SCENARIUSZ_FILMU.md](SCENARIUSZ_FILMU.md) |
| F4 | Demo lokalnie | ✅ | `./start.sh` (demo) i `./start.sh --bez-demo` (lab mentorów) |
| T1 | Technologie open source | ✅ | Orkiestracja w Pythonie, praca sieciowa w nmapie (C); pomiar w PERFORMANCE.md |

## F. Walidacja (sekcja 6): co sprawdzą organizatorzy

| ID | Punkt walidacji | Status | Na czym polegamy |
|---|---|---|---|
| V1 | Wykrycie aktywnych hostów | ✅ | R3, test skali |
| V2 | Identyfikacja usług | ✅ | R4, lab mentorów 5/5 |
| V3 | Fingerprinting HTTP/HTTPS | ✅ | R5 |
| V4 | CMS-y i technologie | ✅ | R6 |
| V5 | Ciekawe nagłówki i ciasteczka | ✅ | Flagi „Ciekawe nagłówki”, „Ciekawe ciasteczka”, braki nagłówków bezpieczeństwa |
| V6 | Własne sygnatury | ✅ | R10, S1 |
| V7 | Porównanie między skanami | ✅ | R8, R9, lab mentorów 7/7 zmian |
| V8 | Hosty niestabilne | ✅ | N2, N4 |
| V9 | Bezpieczeństwo skanera | ✅ | scope_guard na każdej ścieżce (też agent i MCP), T3 maksimum, limity, tylko GET, audyt z łańcuchem skrótów |
| V10 | Czytelność dashboardu | ✅ | R15 |
| V11 | Import i eksport | ✅ | M2, M11 |
| V12 | Role | ✅ | R12, R13, odmowy w audycie |

## G. Pytania z briefu i nasze odpowiedzi (do opisania w dokumentacji)

| Pytanie z briefu | Planowana odpowiedź | Etap |
|---|---|---|
| W jaki sposób raportować zmianę? | Zmiana to różnica między obserwacjami w dwóch przebiegach (host, usługa, technologia, nagłówek, ciasteczko, certyfikat). Znikająca usługa najpierw „niepotwierdzona”, dopiero po spełnieniu reguły „usunięta”. Widok różnic, eksport i opcjonalnie finding informacyjny w DefectDojo | P5 |
| Jak określić pewność identyfikacji technologii? | Wynik 0–100 liczony z liczby i siły niezależnych dowodów (np. nagłówek + ciasteczko + hash favicony + fragment HTML); lista dowodów widoczna w UI | P4 |
| Po jakim czasie braku odpowiedzi raportować host jako nieaktywny? | Konfigurowalna reguła: „nieaktywny” po N kolejnych przebiegach bez odpowiedzi i/lub po czasie T (domyślnie np. N = 3, T = 7 dni); „niestabilny”, gdy odpowiedzi przeplatają się w ostatnich M przebiegach; powtórzenia pomiaru przed zmianą stanu | P5 |

## H. Założenia i pytania do mentorów

Założenia przyjmujemy od razu; po odpowiedzi mentorów poprawiamy kod i tę tabelę.

| # | Niejasność | Nasze założenie | Pytanie do mentorów |
|---|---|---|---|
| Q1 | „Tworzenie i obsługa różnych ról” (pkt 12) | Administrator tworzy role z listy uprawnień w konsoli, poza czterema rolami z pkt 13 | Czy wystarczą cztery stałe role, czy oczekujecie edytora ról? |
| Q2 | Dozwolone techniki discovery (ICMP, ARP, UDP) i porty | Tylko porty z listy organizatora; ICMP i TCP SYN domyślnie, UDP tylko na wybranych portach | Czy w środowisku testowym wolno używać ICMP i UDP? Lista portów? |
| Q3 | Limity tempa | Domyślnie umiarkowane (timing nie agresywniejszy niż T3, limit pakietów na sekundę konfigurowalny) | Jakie limity ruchu obowiązują w środowisku testowym? |
| Q4 | Format importu i eksportu JSON/CSV | Własny, udokumentowany format; adapter na format organizatora po jego otrzymaniu | Kiedy będzie przykładowy format? |
| Q5 | Domeny: tylko rozwiązanie DNS czy też enumeracja subdomen | Rozwiązujemy podane domeny; enumeracja subdomen (pasywna) poza linią cięcia | Czy oczekujecie wyszukiwania subdomen? |
| Q6 | „Pola z danymi wrażliwymi” (pkt 16) | Wartości ciasteczek, nagłówki mogące nieść tokeny, fragmenty treści, notatki, poświadczenia, tokeny integracji | Czy adresy IP i nazwy hostów też uznajecie za wrażliwe? |
| Q7 | Wersja DefectDojo i sposób eksportu | API v2, findingi „Info” i evidence, nmap XML przez wbudowany parser | Jaka wersja DefectDojo będzie w środowisku testowym? |
| Q8 | IPv6 | Tylko IPv4 w prototypie | Czy środowisko testowe ma IPv6? |
| Q9 | Kto czyta dziennik audytu | Administrator; pozostałe role nie | Czy audytor (osobna rola tylko do audytu) jest potrzebny? |

## I. Sprzeczności z dotychczasową specyfikacją (rozstrzygnięte na korzyść briefu)

| Dotychczas | Teraz | Źródło |
|---|---|---|
| Role `admin`, `manager`, `auditor` | Cztery role z briefu + `agent` | Brief pkt 13 |
| „L2 i L3 wymagają zgody człowieka z rolą admin” | Zgoda: `administrator` albo `editor` (decyzja Bartka 21.11) | Polecenie P0 |
| Konsola menedżera, raporty „W skrócie” dla zarządu, pseudonimizacja pracowników | Usunięte; jedna konsola dla zespołu IT/bezpieczeństwa | Brief: „narzędzie dla zespołu bezpieczeństwa” |
| Compliance prawny (KSC, RODO, ISO…), rejestr ryzyk governance, Artemis, film demo | Usunięte | Poza briefem |
| Host „missing” po jednym przebiegu bez odpowiedzi | Reguła N przebiegów / czas T, stan „niestabilny” | Brief, pytanie o nieaktywne hosty |
| nmap `-T4` | Domyślnie nie agresywniej niż T3, limity konfigurowalne | Brief: „bezpieczny skan”, K4 |
| Zakres skanu tylko w pliku `rules/scope.yaml` | Cele z formularza i plików, przez scope_guard | Brief pkt 1, 11 |
| Rdzeń: dopasowanie CVE i scoring ryzyka | Rdzeń: discovery, fingerprinting, zmiany; CVE jako wzbogacenie | Brief, kryteria |
| DefectDojo: brak w planie | Obowiązkowe | Brief, K2 |
