# Sentinel ASI: mapa drogowa

## Nie zdążyliśmy, projekt gotowy

Na sprint finałowy świadomie odłożyliśmy: harmonogram z oknami czasowymi, własne sygnatury,
szyfrowanie w spoczynku, profil pory dnia, ocenę ciekawości, samodzielne działania Sentka i test endpointu przez
agenta. To są możliwe kolejne zadania po oddaniu działającego rdzenia. Detekcja technologii
z wbudowanego silnika ProjectDiscovery `httpx` także pozostaje do integracji; obecny
fingerprint wykorzystuje bibliotekę Python `httpx` i nie zgaduje technologii własnymi
sygnaturami.

Ten plik zbiera to, co świadomie zostaje poza zakresem hackathonu, oraz kolejność, w jakiej
odcinamy zakres, gdy zabraknie czasu. Plan etapów: [ARCHITECTURE.md, sekcja 19](ARCHITECTURE.md#19-plan-pracy-i-linia-cięcia).

## Linia cięcia

**Nigdy nie tniemy:** discovery na skalę, fingerprinting HTTP, porównanie skanów, DefectDojo,
role, szyfrowanie, bezpieczeństwo skanera (scope_guard, limity tempa, audyt, kill switch).
Test bezpieczeństwa agenta (moduł 19) zostaje zawsze, bo już działa.

Gdy zabraknie czasu, odpada od dołu tej listy (pierwsza do odcięcia jest pozycja 7):

1. nmap XML eksportowany do DefectDojo parserem DefectDojo
2. Raporty agenta ze skanów
3. Test endpointu AI przez agenta (promptfoo, L3)
4. Sentek w konsoli zespołu IT
5. Grupowanie podobnych usług
6. Profil dostępności według pory dnia
7. Ocena „ciekawości” obserwacji

## Usunięte po zmianie kierunku

Te kierunki istnieją w historii Git (do scalenia PR #29 włącznie) i nie są dalej rozwijane:
konsola menedżera i rola `manager`, dane pracowników i pseudonimizacja, mapa organizacji z
działami, „Aktualny obraz” i prośby menedżera o skan, compliance prawny i frameworki (KSC, RODO,
KRI, ISO, NIST, AI Act), rejestr ryzyk governance, widok z zewnątrz (Artemis, moje.cert.pl),
film demo z lektorem, ogólne discovery systemów AI w infrastrukturze.

## Po hackathonie

### Skanowanie i skala

- Pipeline skanów przez `mcp-scanner` (#27): worker jako klient MCP z własną tożsamością,
  `worker-scans` bez dostępu do sieci celów.
- Rozproszone sondy skanujące w kilku segmentach sieci, sterowane centralnie (mTLS).
- IPv6, pasywny DNS i inne źródła pasywne, gdy zostaną udostępnione.
- Partycjonowanie tabel obserwacji i historii przy milionach rekordów.
- Przeniesienie gorących ścieżek przetwarzania do Go, jeśli pomiary z `docs/PERFORMANCE.md`
  to uzasadnią.

### Poświadczenia i agent

- Pełne odwołanie certyfikatów SSH przez listy KRL (dziś certyfikat wydany przed kill switchem
  działa do końca TTL 15 min).
- Auto-unseal OpenBao przez KMS albo HSM (dziś tylko tryb demo).
- Feedy OVAL dystrybucji Linuksa: backporty bez ręcznej weryfikacji.

### Tożsamość

- Federacja Keycloak z AD i Entra ID, synchronizacja grup na role.
- WebAuthn jako domyślne MFA.
- Osobna instancja PostgreSQL dla Keycloaka.

### Integracje

- Ticketing (Jira, GLPI), powiadomienia Slack i Teams.
- Dwukierunkowa synchronizacja statusów z DefectDojo.
- SecureCodeBox jako alternatywny wykonawca skanów w Kubernetes.

### AI

- Większy model lokalny na sprzęcie z GPU, wybierany tym samym eval.
- Testy MITRE ATLAS dla agentów z narzędziami.
