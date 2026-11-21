# Stan wymagań sprintu finałowego

Stan na 2026-11-21. Procenty są samooceną pokrycia wymagań z sześciu bloków A–F,
nie przewidywaną punktacją jury. Kryterium „działa” oznacza zweryfikowany kod lub
lokalną usługę; niezaliczone pomiary są oznaczone osobno.

| Kategoria oceny | Pokrycie | Stan |
|---|---:|---|
| A. Discovery i skala | 75% | IP/CIDR/domeny w liście celów, adaptacyjne paczki, dwa workery, nmap T3 i limit pakietów/s, postęp oraz ETA. Test /18 objął 16 384 adresy i 40 hostów z symulowanym adapterem; pomiar rzeczywistego /18 w demo-lab nie powstał. |
| B. Fingerprint WWW, flagi i własne sygnatury | 90% | Biblioteka Python `httpx`: tytuł, status, nagłówki, nazwy ciasteczek, certyfikat TLS, przekierowanie, hash favicony, `/admin` i `/login`, staging, reguły ciekawych nagłówków i ciasteczek, liczba dowodów. Wbudowane sygnatury w `rules/signatures.yaml` i własne z konsoli (Discovery → Sygnatury detekcyjne: sprawdzenie, zapis, usunięcie, audyt, RBAC `scan:run`), ten sam walidator (tylko GET, typy z briefu). Na labie mentorów rozpoznane WordPress, DVWA, Gitea, RabbitMQ, phpMyAdmin, Nginx Proxy Manager, Traefik, httpbin. Wbudowana detekcja technologii binarki ProjectDiscovery `httpx` nie jest podłączona. |
| C. Porównanie i stan hostów | 100% | Dowolne dwa przebiegi, zmiany hostów, usług, technologii i nagłówków; stany aktywny, niestabilny, niepotwierdzony, nieaktywny po domyślnie trzech brakach; widok i JSON/CSV. |
| D. Import, eksport, nadpisania | 100% | Formularz celów z walidacją i podglądem, ręcznie/CSV/JSON; import wyników JSON/CSV/nmap XML; eksport wyników i różnic JSON/CSV; nadpisania w osobnej tabeli scalane przy odczycie. |
| E. Lokalny DefectDojo | 100% | Profil Docker Compose uruchomiony lokalnie; API v2 zweryfikowane przez utworzenie findingu `Info` i pominięcie duplikatu. Eksport nmap XML stanowi drogę awaryjną. |
| F. Pulpit i demo | 95% | Najważniejsze findingi, zmiany, panele i staging, niestabilne hosty, ostatnie skany z czasem i ETA, stan DefectDojo; README i DEMO_GUIDE uzupełnione. Pełny scenariusz dwóch skanów z żywą zmianą w demo-lab wymaga końcowej próby. |

## Założenia i granice

- Cele dodane w UI są podzbiorem zakresu dopuszczonego przez `rules/scope.yaml` albo
  `rules/scope.demo.yaml`; formularz nie rozszerza uprawnień do skanowania.
- `packets_per_second` jest górnym limitem nmap rozdzielonym między równoległe workery;
  domyślnie 100 pakietów/s i dwa workery, najwyżej profil T3.
- Host, który nie odpowiada w jednym przebiegu, jest od razu pokazany jako znikający
  w porównaniu, lecz stan „nieaktywny” dostaje dopiero po N kolejnych przebiegach.
- Nagłówki i ciasteczka są danymi niezaufanymi; przechowywane są skrócone nagłówki oraz
  nazwy ciasteczek bez ich wartości. `technologies` pozostaje pustą listą do czasu
  integracji ProjectDiscovery `httpx`.
- DefectDojo działa tylko w lokalnej sieci Compose. Adres zewnętrzny jest odrzucany przez
  klienta integracji. Token i hasła są w ignorowanym `.env`.
- Zmiany ręczne nadpisują pola `name`, `state` i `note` przy odczycie wyniku. Nowe skany
  nie kasują tabeli nadpisań.

## Otwarte braki

1. Pomiar prawdziwego skanu /18 narzędziem nmap na laboratorium >10 000 adresów;
   [docs/PERFORMANCE.md](docs/PERFORMANCE.md) podaje wyłącznie czas silnika z atrapą sieci.
2. Detekcja technologii przez ProjectDiscovery `httpx` i jej włączenie do porównań.
3. Pełna próba scenariusza demo z wyłączeniem usługi między dwoma skanami.
4. Modułu organizacji i dashboardu menedżera nie ma w tej wersji (usunięte w c1299e6 jako
   spoza briefu).

Test na laboratorium od mentorów i instrukcja odtworzenia: [docs/LAB_TEST.md](docs/LAB_TEST.md).
