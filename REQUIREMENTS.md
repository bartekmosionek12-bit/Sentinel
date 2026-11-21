# Stan wymagań sprintu finałowego

Stan na 2026-11-21. Procenty są samooceną pokrycia wymagań z sześciu bloków A–F,
nie przewidywaną punktacją jury. Kryterium „działa” oznacza zweryfikowany kod lub
lokalną usługę; niezaliczone pomiary są oznaczone osobno.

| Kategoria oceny | Pokrycie | Stan |
|---|---:|---|
| A. Discovery i skala | 75% | IP/CIDR/domeny w liście celów, adaptacyjne paczki, dwa workery, nmap T3 i limit pakietów/s, postęp oraz ETA. Test /18 objął 16 384 adresy i 40 hostów z symulowanym adapterem; pomiar rzeczywistego /18 w demo-lab nie powstał. |
| B. Fingerprint WWW i flagi | 85% | Biblioteka Python `httpx`: tytuł, status, nagłówki, nazwy ciasteczek, certyfikat TLS, przekierowanie, hash favicony, `/admin` i `/login`, staging, reguły ciekawych nagłówków i ciasteczek, liczba dowodów. Wbudowana detekcja technologii binarki ProjectDiscovery `httpx` nie jest podłączona. |
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
4. Test na laboratorium organizatorów (lab.zip): przekierowanie na porcie 80/443 gubi
   WordPress i DVWA (porównanie adresu w `fingerprint.py`), a listy portów w
   `rules/discovery.yaml` nie obejmują portów labu (m.in. 2223, 3001, 5672, 8085–8090,
   15432, 15672). Moduł organizacji i dashboard menedżera nie wchodzą do tej wersji
   (usunięte w c1299e6 jako spoza briefu).
