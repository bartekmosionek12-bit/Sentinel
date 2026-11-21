# Przewodnik demo

Pokaz na żywo na scenariuszach z [DEMO.md](DEMO.md). Film demo z lektorem usunęliśmy przy
zmianie kierunku (21.11.2026); scenariusz prezentacji pod brief AGH powstaje w P12
([ROADMAP.md](ROADMAP.md)).

## Pokaz na żywo

### Scenariusz sprintu: dwa przebiegi i lokalny DefectDojo

1. Uruchom `python scripts/init_env.py --demo` i `./scripts/seed_demo.sh`. Zaloguj się
   jako `admin` do `/admin/skany`. Hasło i TOTP są w ignorowanym
   `data/demo-credentials.env`. Konto `manager` korzysta z `/dashboard/`, a `auditor`
   ma odczyt i dziennik audytu; konsola respektuje uprawnienia każdej roli.
2. Pierwszy przebieg powstaje podczas seedowania. W widoku „Skany” zobacz czas,
   paczki discovery, ETA i eksport JSON/CSV. W „Zasoby” sprawdź hosty i flagi WWW.
3. Zmień laboratorium: `docker compose --profile demo stop lab-proxy`, potem uruchom
   skan z przycisku „Uruchom skan zakresu”. W „Porównaj dwa przebiegi” wybierz
   poprzedni i obecny. `172.30.99.11` pojawi się jako znikający. Po trzech kolejnych
   brakach odpowiedzi jego stan będzie „nieaktywny”. Po pokazie przywróć usługę przez
   `docker compose --profile demo up -d lab-proxy`.
4. W formularzu celów wpisz `172.30.99.10` i użyj „Podgląd”, potem dodaj cel.
   Import celów przyjmuje CSV z kolumną `target` albo JSON z listą `targets`.
   Import wyników przyjmuje JSON, CSV (`ip,port,product,version`) i nmap XML.
   Po imporcie wybierz host w „Edycja wyniku”, dodaj notatkę i pokaż znacznik
   „zmienione ręcznie”; kolejny skan jej nie usuwa.
5. Uruchom lokalny profil `docker-compose.defectdojo.yml` i
   `./scripts/bootstrap_defectdojo.sh` według README. Zaznacz flagi w panelu
   DefectDojo i wyślij jako findingi `Info`. Ponowne wysłanie daje licznik duplikatów.
   Przy problemie z API pobierz z tego samego ekranu nmap XML i zaimportuj go
   w lokalnym DefectDojo.

Założenie: zakres w demo jest ograniczony do `172.30.99.0/24`; skan nie dotyka
innych sieci. W benchmarku `/18` z [PERFORMANCE.md](PERFORMANCE.md) adapter sieci
był symulowany, więc na scenie nie przedstawiaj go jako czasu rzeczywistego nmap.

1. `./scripts/seed_demo.sh`, potem `python3 scripts/check_demo.py http://localhost:8080`.
   Skrypt loguje się jak przeglądarka (Keycloak, hasło, TOTP) i sprawdza ścieżkę krytyczną,
   w tym Sentka, cztery role (odmowy 403 w audycie) i kolejkę akcji L2+ dla `editor`.
2. Scenariusze krok po kroku: [DEMO.md](DEMO.md) (zero-day, agent z certyfikatem SSH, cztery
   role i edytor ról, zatruty host i test agenta).
