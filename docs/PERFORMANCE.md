# Wydajność discovery

Test 2026-11-21, lokalny benchmark silnika na Pythonie 3.12 i SQLite w pamięci. Zakres
`10.77.0.0/18` obejmuje 16 384 adresy; symulator adaptera nmap zwraca 40 aktywnych hostów
rozmieszczonych w całym zakresie. Test używa rzeczywistego `ScanService`, `scope_guard`,
zapisu akcji i inwentarza, lecz **nie mierzy czasu pracy nmap ani sieci**. Przepustowość
rzeczywistego laboratorium pozostaje do zmierzenia po uruchomieniu skanera w Docker Compose.

| Metryka | Wynik |
|---|---:|
| Adresy / wykryte hosty | 16 384 / 40 |
| Paczki discovery | 169 |
| Czas ścienny | 0,36 s |
| Czas CPU procesu | 0,36 s |
| Szczyt RSS procesu | 120,4 MiB |
| Równoległe workery / limit nmap | 2 / 100 pakietów/s łącznie |

Paczki startują od 64 adresów, rosną do 256 przy szybkim przebiegu i maleją przy
wolnym. Każda paczka ma osobną decyzję `scope_guard`, czas, status i commit. Podsumowanie
przebiegu zawiera liczbę przetworzonych adresów i ETA. Usługi są skanowane `nmap -sV`
wyłącznie na wykrytych hostach. Profil nmap to T3.

Benchmark uruchomiono skryptem lokalnym z adapterem symulowanym; wyniki nie są deklaracją
wydajności skanu sieciowego. Dla odtworzenia realnego pomiaru należy przygotować
autoryzowane laboratorium /18 i uruchomić zwykły skan z konsoli, obserwując `scan_run.summary`.

## Pomiar w laboratorium /18 (22.11.2026)

Rzeczywisty nmap w izolowanej przestrzeni sieciowej `asi-lab` (skrypt
`scripts/perf_discovery.py`), zakres `10.200.0.0/18`, ustawienia `workers=16`, `max_rate=1000`,
T3, wszystkie fazy discovery (sweep, skan usług, fingerprint HTTP/TLS, ponowna próba).

| Metryka | Wynik |
|---|---:|
| Adresy / aktywne hosty | 16 384 / 48 |
| Otwarte usługi / fingerprinty HTTP / flagi | 72 / 24 / 80 |
| Czas ścienny (całość) | 6 217 s (ok. 104 min) |
| Czas sweepu | 6 158 s, 728 paczek (16–256 adresów, średnio 135 s) |
| Skan usług | 48 zadań, średnio 3,5 s |
| Przepustowość | 2,6 adresu/s |
| CPU: Python / nmap | 5,7 s / 1 340,7 s |
| Szczyt RSS: Python / jeden proces nmap | 81,8 MiB / 81,7 MiB |

Prawie cały czas to sweep pustych adresów. Najpewniej nmap czeka na odpowiedź każdego z 40 portów
discovery przy T3, a puste adresy w laboratorium nie odpowiadają ani RST, ani ICMP, więc każdy
kończy się limitem czasu. Paczki dlatego zostały małe (do 256). Python zużył 5,7 s CPU, czyli
orkiestracja nie jest wąskim gardłem. Szybciej: mniej portów discovery, wyższy `max_rate`
w granicach `limits` albo T4 (zablokowane celowo dla bezpieczeństwa).

