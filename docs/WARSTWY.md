# Trzy warstwy skanowania podatności i IAM

Skanowanie podatności jest podzielone na trzy wyraźnie oddzielone warstwy. Każda ma własne
uprawnienie, własny endpoint i własny przycisk w konsoli. **Żadna nie startuje sama**: nie ma
harmonogramu ani automatu, który uruchamia warstwę, a warstwa 1 nie zleca warstwy 2
(test `test_layers_never_start_by_themselves`).

| | Warstwa 1 | Warstwa 2 | Warstwa 3 |
|---|---|---|---|
| Co robi | deterministyczny skan narzędziami red team | model językowy czyta logi warstwy 1 i daje zalecenia | autonomiczny agent AI sam planuje sprawdzenia |
| Narzędzia | nmap `-sV` + bezpieczne skrypty NSE, nuclei | brak (tylko zapisane wyniki) | narzędzia MCP ze zdolności agenta |
| Model językowy | nie | opcjonalnie (domyślnie wyłączony) | tak |
| Uprawnienie | `redteam:layer1` | `redteam:layer2` | `redteam:layer3` |
| Uruchomienie | „Uruchom warstwę 1” (`POST /api/redteam/layer1/runs`) | „Analizuj (warstwa 2)” (`POST /api/redteam/runs/{id}/analysis`) | polecenie w zakładce Agent AI (`POST /api/agent/tasks`) |
| Wynik | grupy podatności na stronie przebiegu i na pulpicie, DefectDojo | ryzyko, kroki naprawy i kolejność działań | plan, zgody, wyniki kroków |

## Kto ma dostęp

Domyślnie **tylko administrator** (rola `administrator` ma `*`). Uprawnienia warstw są
zarezerwowane: nie można ich dodać do roli własnej (`RESERVED_PERMISSIONS`), więc jedyną drogą
dla innych osób jest **delegacja** w panelu IAM:

- konkretna osoba (konto człowieka; administratora nie trzeba delegować),
- jedna warstwa (1, 2 albo 3),
- konkretne podsieci (jednostka) w formacie CIDR; każda musi leżeć w zakresie skanowania,
- okno czasu od–do, najwyżej 30 dni,
- powód, zapisywany w audycie.

Delegacja działa tylko w swoim oknie i tylko po logowaniu z MFA. Endpoint sprawdza każdy cel:
cel spoza podsieci delegacji daje 403 i wpis `access_denied` w audycie. Warstwa 3 dodaje
uprawnienia agenta (`agent:task`, `agent:read`), a przy zatwierdzaniu planu sprawdza, czy każdy
krok leży w podsieciach delegacji. Odwołanie działa od następnego żądania. Nadanie i odwołanie
to wpisy `layer_delegated` i `layer_delegation_revoked` w dzienniku audytu.

Decyzja z 22.11.2026: rola `editor` nie ma już `agent:task`. Agent i warstwy red team są
domyślnie tylko dla administratora; editor zatwierdza dalej akcje L2/L3 zwykłych skanów.

## Panel IAM (`/iam`, „IAM: role i użytkownicy”)

- **Ludzie (human)**: konta z rolami, kolumną „Warstwy skanowania” i nadawaniem ról; tabela
  dostępu do warstw (z roli albo z delegacji); formularz delegacji; lista delegacji ze stanem
  (aktywna, zaplanowana, wygasła, odwołana) i odwołaniem. Same skany nie są w IAM: uruchamia się
  je w Kontrola → Warstwy skanowania, obok Agenta AI.
- **Role i uprawnienia**: macierz i edytor ról własnych.
- **Agent AI i konta techniczne (non-human)**: agent AI jako tożsamość warstwy 3. Jego „rolą” są zdolności (narzędzia, cele,
  najwyższy poziom, limity) nadawane w tym samym miejscu; wchodzą w życie po zaliczonym teście
  bezpieczeństwa agenta. Do tego role techniczne `agent` i `system` (bez uprawnień do API)
  i konta techniczne, które wywołały API.

## Warstwa 1 w szczegółach

Konfiguracja: [`rules/redteam.yaml`](../rules/redteam.yaml). Kod: `app/redteam/engine.py`.

1. Cele: adresy IP i podsieci CIDR w zakresie skanowania. Domeny są odrzucane.
2. Podsieć: odkrycie hostów `nmap -sn` przez `authorize_network` (L1).
3. Każdy host: `scope_guard.authorize` na poziomie **L2 ze zgodą osoby, która uruchomiła
   przebieg** (powód z formularza), potem `nmap -sV -Pn -T3 --max-rate 100 --script …`.
4. Skrypty NSE wyłącznie z listy `ALLOWED_SCRIPTS`: `ssl-cert`, `ssl-enum-ciphers`, `sslv2`,
   `http-methods`, `http-security-headers`, `ssh2-enum-algos`, `smb2-security-mode`,
   `ftp-anon`. Inny skrypt w pliku zatrzymuje start (`ValueError`).
5. Porty HTTP/HTTPS z wyniku nmap: nuclei z tagami `cve, misconfig, exposure, ssl`. Tagi
   eksploatacji (`exploit, rce, sqli, xss, lfi, ssrf, bruteforce, default-login, dos, fuzz…`)
   są zawsze w `-etags`, a wpisanie ich do `tags` zatrzymuje start. Brak binarki nuclei to
   jawna adnotacja „nuclei pominięty” w logu przebiegu; wynik nmap zostaje.
6. Reguły oceny (deterministyczne): przestarzałe protokoły i słabe szyfry TLS, SSLv2,
   certyfikat wygasły, wygasający i z podpisem własnym, ryzykowne metody HTTP, brak HSTS,
   słabe algorytmy SSH, podpisywanie SMB niewymagane, anonimowy FTP, usługi bez szyfrowania,
   wystawione bazy danych, magazyny i pulpity zdalne, wersje poniżej minimalnych.

Bez eksploatacji, brute force i DoS. Kill switch blokuje start skanu hostów, a uruchomione
procesy przerywa wspólny rejestr procesów (jak w discovery). Te same cele i ten sam plik
reguł dają ten sam wynik (test `test_layer1_is_deterministic_and_goes_through_scope_guard`).

### Grupowanie i DefectDojo

Podatności są grupowane po rodzaju problemu (`group_key`, np. `tls_old_protocol`,
`outdated_software:openssh`, `nuclei:<szablon>`). Grupa ma listę wszystkich punktów końcowych
z dowodami i jest sortowana od najpoważniejszej. Do DefectDojo idzie **jeden finding na grupę**
z listą endpointów (engagement „Red team: warstwa 1”), z polem `mitigation` z warstwy 2, jeśli
analiza istnieje. Identyfikator zależy od grupy i zestawu endpointów, więc ponowna wysyłka nie
dubluje zgłoszeń (tabela `defectdojo_export`).

## Warstwa 2 w szczegółach

Kod: `app/redteam/analysis.py`. Uruchamiana wyłącznie przyciskiem przy zakończonym przebiegu.

- Domyślnie **bez modelu** (`REDTEAM_LLM=off`): zalecenia z szablonu reguł dla każdej grupy,
  oznaczone w API i interfejsie jako „szablon reguł (bez modelu)”.
- Opcja na przyszłość: model przez API. `REDTEAM_LLM=local` używa Ollamy (`LLM_MODEL`),
  `REDTEAM_LLM=external` zewnętrznego API (tylko przy `EXTERNAL_LLM_ENABLED=true`).
- Fakty dla modelu to grupy z dowodami i log narzędzi warstwy 1. Przed wysłaniem zawsze
  przechodzą przez anonimizator (adresy IP, domeny, nazwy z inwentarza → znaczniki); pełne
  nazwy wracają dopiero na serwerze. Tekst z narzędzi jest oznaczony jako dane.
- Odpowiedź musi pasować do schematu JSON. Grupy spoza wyników warstwy 1 są odrzucane,
  a grupy pominięte przez model dostają zalecenie z szablonu z adnotacją.

## Warstwa 3

To istniejący agent AI (`/agent`). Zmiana: zadanie zleca tylko osoba z `redteam:layer3`
(administrator albo delegacja), a zgoda na krok poza podsiecią delegacji jest odrzucana.
Pozostałe zabezpieczenia agenta bez zmian: zdolności od administratora, test bezpieczeństwa
przed aktywacją, zgoda człowieka na każdy krok L2+, MCP i scope_guard przy każdym wywołaniu,
poświadczenia just-in-time, kill switch.

## Konta demo

`scripts/demo_users.sh` zakłada oprócz `admin`, `editor`, `modifier` i `viewer` dwa konta
z niższymi uprawnieniami: `analityk` (rola editor) i `operator` (rola modifier). Bez
delegacji nie mają żadnej warstwy; w demo administrator deleguje im warstwę w panelu IAM.
