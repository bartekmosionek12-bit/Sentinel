# Scenariusz filmu demo (2:50)

Film pokazuje najważniejsze funkcje Sentinel ASI w kolejności wag z kryteriów oceny briefu:
najpierw discovery i usługi (30%), potem zmiany w czasie (15%), import, eksport i DefectDojo
(20%), bezpieczeństwo i dashboard (15%), fingerprinting i sygnatury (10%), role i dane (10%),
a na końcu moduł trzech warstw. Wszystko na fikcyjnych danych z sieci demo `172.30.99.0/24`.

Długość: około 2:50. Lektor: około 340 słów, czyli spokojne tempo 130–140 słów na minutę z pauzami na kliknięcia. Skany
trwają dłużej niż film, więc kliknięcie „Uruchom” jest nagrywane na żywo, a wynik pokazujemy
z przebiegu przygotowanego wcześniej (cięcie).

## Przygotowanie przed nagraniem (ok. 20 min)

1. `./start.sh` (tryb demo). Skrypt robi pierwszy przebieg discovery i zakłada konta. Hasła
   i sekret TOTP są w `data/demo-credentials.env`.
2. W pierwszym przebiegu na karcie hosta `172.30.99.13` dodaj notatkę i tag `sklep`
   („Zapisz zmiany”), żeby w drugim przebiegu było widać, że poprawka przetrwała.
3. Drugi przebieg ze zmianą w labie, żeby porównanie miało co pokazać:
   `docker compose --profile demo stop lab-proxy`, w konsoli Discovery → cele
   `172.30.99.0/24` → „Sprawdź cele” → „Uruchom skan”, poczekaj na koniec, potem
   `docker compose --profile demo up -d lab-proxy`.
4. Discovery → Harmonogram: dodaj wpis cykliczny „codziennie 22:00–06:00” na
   `172.30.99.0/24`.
5. `python3 scripts/check_demo.py http://localhost:8080`: sprawdza ścieżkę demo i przy okazji
   zostawia w audycie odmowy 403 dla `viewer`, które pokazujemy w scenie 8.
6. Jako `admin` w Kontrola → Warstwy skanowania uruchom warstwę 1 na
   `172.30.99.0/24` i poczekaj na koniec (kilka minut). Kliknij „Analizuj (warstwa 2)”.
7. Okna przeglądarki, 1920×1080, powiększenie 110%, tryb jasny:
   - karta 1: konsola jako `admin`, Pulpit,
   - karta 2: DefectDojo <http://localhost:8081> (zalogowany, engagement „Sprint final”),
   - osobny profil przeglądarki: konsola jako `viewer`,
   - terminal z dużą czcionką, w folderze repozytorium.
8. Schowek: sygnatura do wklejenia w scenie 5 (poniżej) i lista celów do sceny 2.
9. Nagrywanie: OBS, 1080p, 30 kl./s, osobna ścieżka lektora. Kursor powiększony.

Cele do sceny 2 (ostatni wiersz celowo spoza zakresu):

```
172.30.99.0/24
8.8.8.8
```

Sygnatura do sceny 5 (dopasowuje nagłówek `Server` starego Apache z labu):

```yaml
id: apache-2-4-49
name: Apache 2.4.49 (stara wersja)
kind: technology
match:
  - {type: header, name: server, pattern: "Apache/2\\.4\\.49"}
```

## Scenariusz

| # | Czas | Ekran i akcja | Lektor |
|---|---|---|---|
| 1 | 0:00–0:12 | Ekran logowania: login `admin`, hasło, kod TOTP. Wejście na **Pulpit**: kafelki, „Ostatnie przebiegi discovery”, karta „Warstwa 1: skan podatności”. | „Sentinel ASI to narzędzie do discovery dużych sieci dla zespołu bezpieczeństwa. Logowanie wymaga drugiego składnika, a pulpit od razu pokazuje ostatnie przebiegi i najważniejsze znaleziska.” |
| 2 | 0:12–0:35 | **Discovery → Przebiegi discovery**. Wklej dwa cele. Pokaż pola: workery, pakiety na sekundę, szablon T3, „Zakończ najpóźniej”. Klik **„Sprawdź cele”**: sieć demo dozwolona z liczbą adresów, `8.8.8.8` odrzucony z powodem. Usuń ten wiersz, klik **„Uruchom skan”**. Mignięcie „Wczytaj cele z pliku” (CSV, JSON). | „Cele wpisujemy ręcznie albo wczytujemy z CSV lub JSON: adresy, zakresy i domeny. Zanim cokolwiek wyjdzie do sieci, każdy cel przechodzi przez kontrolę zakresu. Adres spoza zatwierdzonej sieci zostaje odrzucony. Tempo ograniczamy liczbą workerów, limitem pakietów i szablonem nie szybszym niż T3.” |
| 3 | 0:35–1:00 | Cięcie do zakończonego przebiegu. Statystyki: czas, ETA, aktywne hosty. Rozwiń **Paczki** (różne rozmiary, czas, decyzja zakresu). Przewiń do **„Grupy podobnych usług”**. Klik w `172.30.99.10`: karta hosta z usługami i wersjami, fingerprint HTTP (kod, tytuł, nagłówki, ciasteczka, przekierowania), TLS, technologie, flagi z dowodami i pewnością. | „Zakres jest dzielony na paczki, których rozmiar silnik dobiera do zmierzonej szybkości, a nmap działa równolegle. Widzimy czas całego skanu i każdej paczki. Dla aktywnych hostów rozpoznajemy usługi i wersje, a dla stron WWW tytuł, kod odpowiedzi, nagłówki, ciasteczka, certyfikat i przekierowania. Flagi wskazują panele, środowiska testowe i ciekawe nagłówki, zawsze z dowodami i poziomem pewności.” |
| 4 | 1:00–1:20 | **Discovery → Porównanie i stany**. Wykres „Zmiany w czasie”. Wybierz dwa przebiegi: `172.30.99.11` jako zniknięty, zmienione usługi. Przewiń do stanów hostów z historią ✓/✗ (niepotwierdzony, niestabilny). Klik eksport CSV. | „Porównanie dowolnych dwóch przebiegów pokazuje nowe, zniknięte i zmienione hosty i usługi. Host, który przestał odpowiadać, nie jest od razu nieaktywny: najpierw dostaje ponowną próbę, potem jest niepotwierdzony, a nieaktywny dopiero po trzech pustych przebiegach. Wykrywamy też hosty odpowiadające tylko w dzień albo w nocy.” |
| 5 | 1:20–1:38 | **Discovery → Sygnatury detekcyjne**. Wklej YAML ze schowka, „Sprawdź”, „Zapisz”. Klik **„Testuj”** przy nowej sygnaturze: trafienie na `172.30.99.10` z dowodem. Na sekundę **„Inspekcja”**. | „Własne sygnatury piszemy w prostym YAML-u: nagłówek, ciasteczko, tytuł, hash favicony albo ścieżka. Walidator przepuszcza tylko bezpieczne żądania GET. Test działa na zapisanych wynikach, bez żadnego ruchu w sieci.” |
| 6 | 1:38–1:50 | **Discovery → Harmonogram**: istniejący wpis „codziennie 22:00–06:00”. Krótko formularz: częstotliwość, okno, dni, strefa. | „Harmonogram ustawia okno i częstotliwość. Jeśli skan nie zdąży przed końcem okna, zatrzymuje się, zapisuje resztę celów i wraca w następnym oknie.” |
| 7 | 1:50–2:10 | Wróć do przebiegu. Karta `172.30.99.13`: notatka i tag `sklep` z poprzedniego przebiegu, znacznik „zmienione ręcznie”. Pokaż przyciski eksportu JSON, CSV, nmap XML i „Import wyników”. Zaznacz dwa hosty, **„Wyślij do DefectDojo”**. Przełącz na kartę DefectDojo: findingi Info w teście „Discovery”. | „Wyniki można poprawiać: notatki, tagi, krytyczność i status zostają po kolejnych skanach. Eksport jest w JSON, CSV i nmap XML, a import przyjmuje te same formaty. Wybrane hosty wysyłamy do lokalnego DefectDojo jako findingi informacyjne. Ponowna wysyłka nie tworzy duplikatów.” |
| 8 | 2:10–2:25 | Profil `viewer`: menu bez Dziennika audytu i Ról, brak przycisków zapisu (np. przy przebiegu i edycji hosta). Powrót do `admin` → **Kontrola → Dziennik audytu**: wpis `access_denied` dla `viewer`, wpisy `discovery_requested`, `signature_saved`. | „Cztery role z briefu, od odczytu po administrację, plus role własne. Backend sprawdza uprawnienia przy każdym żądaniu, a każda akcja i każda odmowa trafia do dziennika audytu.” |
| 9 | 2:25–2:42 | **Kontrola → IAM**, zakładka Human: trzy warstwy i kto ma dostęp. Formularz „Deleguj warstwę”: `analityk`, warstwa 1, `172.30.99.0/24`, jutro, powód. Klik „Deleguj”. Szybko zakładka Non-human (agent AI i jego zdolności). Potem **Kontrola → Warstwy skanowania** → przebieg warstwy 1: pogrupowane podatności, karta analizy warstwy 2, „Wyślij grupy do DefectDojo”. | „Ponad brief: skan podatności w trzech oddzielnych warstwach. Deterministyczny skan narzędziami, analiza jego logów z zaleceniami i agent AI. Żadna nie startuje sama. Domyślnie ma je tylko administrator, który deleguje konkretną osobę, na konkretną podsieć i na określony czas.” |
| 10 | 2:42–2:50 | Terminal: `docker compose exec db psql -U sentinel -d sentinel -c "select ip, left(services::text, 50) from observation limit 3;"` Widać `enc:v1:…`. Plansza końcowa z nazwą i adresem repozytorium. | „Wyniki skanów są w bazie zaszyfrowane. Sentinel ASI: bezpieczne discovery dużej sieci, od celu do DefectDojo.” |

## Wersja awaryjna (2:00)

Gdy trzeba skrócić: pomiń scenę 6 (harmonogram, zostaw jedno zdanie lektora nad sceną 4)
i scenę 10 (szyfrowanie, zdanie przenieś do sceny 8). Sceny 9 nie skracaj poniżej 10 s,
bo to jedyne miejsce, gdzie widać IAM i trzy warstwy.

## Na co uważać

- Nie pokazuj na ekranie `.env`, `data/demo-credentials.env` ani sekretu TOTP.
- `8.8.8.8` w scenie 2 jest tylko w podglądzie: „Sprawdź cele” nie wysyła ruchu, a przed
  „Uruchom skan” wiersz jest usunięty.
- Jeśli DefectDojo nie wstał (limit Docker Hub), w scenie 7 pokaż eksport nmap XML i powiedz,
  że to droga importu do DefectDojo.
- Po nagraniu: `docker compose --profile demo up -d lab-proxy`, żeby lab wrócił do stanu
  wyjściowego.
