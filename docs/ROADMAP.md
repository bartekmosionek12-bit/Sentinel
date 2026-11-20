# Sentinel ASI: mapa drogowa

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
- Auto-unseal OpenBao przez KMS albo HSM zamiast klucza w `.env` (dziś: tylko tryb demo).
- Pełne odwołanie certyfikatów SSH przez listy KRL dystrybuowane na hosty produkcyjne.
- Feedy OVAL dystrybucji Linuksa: rozstrzyganie backportów bez ręcznej weryfikacji.
- Pozostałe narzędzia odkrywania: subfinder z kluczami API źródeł pasywnych, skan IPv6.

### Compliance

- Pakiety KRI, DORA i Cyber Resilience Act jako pełne zestawy reguł (dziś szkielety).
- NIST CSF 2.0 z pełnym mapowaniem.
- Przegląd prawny pakietów przez prawnika, z historią wersji i datą stanu prawnego.
- Sandbox WebAssembly dla wtyczek z regułami: reguły od społeczności bez dostępu do sieci,
  plików i bazy.

### AI

- Większy model lokalny na sprzęcie z GPU, wybierany tym samym eval.
- Eval z rubryką ocenianą przez kilku ludzi i z większą liczbą przypadków.
- Testy MITRE ATLAS dla agentów z narzędziami (nie tylko chatbotów).

### Integracje i skala

- Prawdziwe konektory AD, Entra ID, Intune lub Jamf, CMDB (np. ServiceNow, NetBox), DHCP i DNS.
- Ticketing (Jira, GLPI) dla działań naprawczych z terminami.
- Partycjonowanie tabel historii i findingów powyżej 50 tys. zasobów.
