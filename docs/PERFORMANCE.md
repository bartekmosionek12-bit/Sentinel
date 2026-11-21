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
