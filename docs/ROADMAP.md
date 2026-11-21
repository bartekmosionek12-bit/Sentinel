# Sentinel ASI: mapa drogowa

## Nie zdążyliśmy, projekt gotowy

Na sprint finałowy świadomie odłożyliśmy: harmonogram z oknami czasowymi, własne sygnatury,
szyfrowanie w spoczynku, profil pory dnia, ocenę ciekawości, Sentka i test endpointu przez
agenta. To są możliwe kolejne zadania po oddaniu działającego rdzenia. Detekcja technologii
z wbudowanego silnika ProjectDiscovery `httpx` także pozostaje do integracji; obecny
fingerprint wykorzystuje bibliotekę Python `httpx` i nie zgaduje technologii własnymi
sygnaturami.

Ten plik zbiera to, co świadomie zostaje poza zakresem hackathonu, oraz kolejność, w jakiej
odcinamy zakres, gdy zabraknie czasu. Plan etapów: [ARCHITECTURE.md, sekcja 19](ARCHITECTURE.md#19-plan-pracy-i-linia-cięcia).

## Linia cięcia

Gdy brakuje czasu, odpada od dołu tej listy: pierwsza do odcięcia jest pozycja 13, potem 12
i tak dalej. Pozycje 8–13 to kolejność ze specyfikacji, pozycje 2–7 to moja propozycja.

1. Ścieżka krytyczna, `scope_guard`, RBAC w backendzie, poświadczenia poza LLM, scenariusz
   zero-day: **nigdy nie tniemy**.
2. Agent z planem i zatwierdzeniem, OpenBao z certyfikatem SSH 15 min, kill switch.
3. Konsola menedżera: strona główna, tabele, karta urządzenia, „Nieznane i niepotwierdzone”.
4. Raporty dwuwarstwowe i skrzynka menedżera.
5. Compliance: pakiety KSC i RODO art. 32, mapowania ISO 27001 i CIS, kwestionariusz.
6. Mapa interaktywna z przybliżaniem.
7. AI Security dla infrastruktury i podatny chatbot w demo-lab.
8. KRI, DORA, CRA i NIST CSF jako szkielety reguł.
9. Federacja Keycloak z AD i Entra ID.
10. Rola `auditor`.
11. Formalna akceptacja ryzyka przez menedżera (`risk:accept`).
12. Dynamiczne konta chmurowe w OpenBao.
13. Sandbox WebAssembly dla wtyczek z regułami.

Termin oddania nie ma konkretnej daty (stan na 2026-11-20: „czasu jest dużo”), więc planujemy
wszystkie etapy, a ta lista działa jako plan awaryjny.

## Wizja rozwoju (po hackathonie)

### Tożsamość i dostęp

- Federacja z AD i Entra ID w Keycloak, synchronizacja grup na role.
- Rola `auditor` z eksportem paczki dowodów (audit log, wyniki, raporty) podpisanej cyfrowo.
- Formalna akceptacja ryzyka przez menedżera z terminem wygaśnięcia i przypomnieniami.
- WebAuthn jako domyślne MFA dla adminów.
- Osobna instancja PostgreSQL dla Keycloaka (dziś ta sama instancja, osobni użytkownicy i schematy).
- Logowanie bez Keycloaka (`AUTH_PROVIDER=local`) dla bardzo małych instalacji.
- Certyfikat z ACME albo firmowego CA w profilu `tls` (w Etapie 9 certyfikat lokalny Caddy).

### Poświadczenia i skanowanie

- Dynamiczne konta chmurowe (AWS, Azure, GCP) w OpenBao, skan konfiguracji chmury.
- Auto-unseal OpenBao przez KMS albo HSM zamiast klucza w wolumenie `openbao-init` (dziś:
  tylko tryb demo).
- Silnik `database` w OpenBao: konto tylko do odczytu na czas zadania agenta.
- Pipeline skanów przez `mcp-scanner` (Etap 9, jeśli zostanie czas; inaczej tutaj): worker jako
  klient MCP z własną tożsamością `sentinel-pipeline`, polityka zatwierdza automatycznie tylko
  L1, a L2 i L3 nadal czekają na admina. Dziś przez MCP idzie tylko agent, a pipeline woła
  adaptery bezpośrednio, zawsze przez `scope_guard`. Po migracji `worker-scans` traci dostęp
  do sieci z celami i zostaje w niej tylko `mcp-scanner` (stan zaakceptowany 2026-11-21, #27).
- Narzędzia agenta `resolve_dns`, `check_tls`, `check_compliance`, `probe_ai_endpoint` i
  adaptery subfinder, dnsx, httpx, naabu, testssl.sh.
- Pełne odwołanie certyfikatów SSH przez listy KRL (najpierw w demo-lab, potem dystrybucja na
  hosty produkcyjne). Dziś certyfikat wydany przed kill switchem działa do końca TTL 15 min.
- Feedy OVAL dystrybucji Linuksa: rozstrzyganie backportów bez ręcznej weryfikacji.
- Pozostałe narzędzia odkrywania: subfinder z kluczami API źródeł pasywnych, skan IPv6.

### Compliance

- Pakiety KRI, DORA i Cyber Resilience Act jako pełne zestawy reguł (dziś szkielety).
- NIST CSF 2.0 z pełnym mapowaniem.
- Przegląd prawny pakietów przez prawnika, z historią wersji i datą stanu prawnego.
- Sandbox WebAssembly dla wtyczek z regułami: reguły od społeczności bez dostępu do sieci,
  plików i bazy.

### Raporty

- Baner zero-day i powiadomienia przez SSE zamiast odpytywania co 5 s.
- Doręczanie raportów i powiadomień do Slacka i Teams (PDF, digesty i e-mail w Etapie 6).

### AI

- Większy model lokalny na sprzęcie z GPU, wybierany tym samym eval.
- Eval z rubryką ocenianą przez kilku ludzi i z większą liczbą przypadków.
- Testy MITRE ATLAS dla agentów z narzędziami (nie tylko chatbotów).
- Klasyfikator parafraz bagatelizujących ryzyko zamiast list zwrotów (dziś reguły słownikowe).

### Widok z zewnątrz (moduł 20, ARCHITECTURE §24)

- Plan na Etap 8 (#26). Jeśli zabraknie czasu, na hackathonie zostaje import z pliku (mock
  moje.cert.pl) i korelacja, a tu trafiają: Artemis w profilu `artemis` (`artemis_local`),
  narzędzie MCP `external_scan` w L2 i sonda zewnętrzna `artemis_probe` z kanałem mTLS.
- Sonda zewnętrzna na stałe: Artemis na serwerze poza siecią organizacji, harmonogram skanów
  z zewnątrz i porównanie w czasie.

### Integracje i skala

- Prawdziwe konektory AD, Entra ID, Intune lub Jamf, CMDB (np. ServiceNow, NetBox), DHCP i DNS.
- Ticketing (Jira, GLPI) dla działań naprawczych z terminami.
- Partycjonowanie tabel historii i findingów powyżej 50 tys. zasobów.
