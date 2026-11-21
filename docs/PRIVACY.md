# Prywatność danych pracowników

Ten dokument opisuje, jakie dane osobowe przetwarza Sentinel ASI, po co i jak je chroni.
Podstawę prawną i okresy retencji musi zweryfikować inspektor ochrony danych (IOD) organizacji,
która wdraża system. Ten dokument nie jest opinią prawną.

## Zakres

Sentinel przechowuje tylko powiązanie urządzenia z osobą:

| Dane | Skąd | Po co |
|---|---|---|
| imię i nazwisko, stanowisko, dział | katalog (AD lub Entra ID) | żeby wiedzieć, kogo zapytać o urządzenie i kto naprawia podatność |
| przypisanie urządzenia (użytkownik, właściciel) | MDM, CMDB | to samo |
| identyfikator konta w katalogu | katalog | żeby scalać kolejne synchronizacje |

Sentinel **nie zbiera** aktywności pracowników: historii przeglądania, logowań, treści,
lokalizacji ani czasu pracy. Skany sprawdzają urządzenia i usługi, nie osoby.

## Cel i podstawa prawna (do weryfikacji przez IOD)

Cel: zarządzanie bezpieczeństwem systemów informacyjnych i obsługa incydentów, czyli obowiązki
z ustawy o krajowym systemie cyberbezpieczeństwa (KSC) i NIS2. Proponowana podstawa: art. 6
ust. 1 lit. c RODO (obowiązek prawny) albo lit. f (prawnie uzasadniony interes administratora
w zapewnieniu bezpieczeństwa sieci, motyw 49 RODO).

## Kto widzi nazwiska

- Uprawnienie `personal_data:view` (domyślnie administrator i menedżer). Audytor widzi tylko
  pseudonimy „Pracownik #N”.
- Każda odpowiedź API z nazwiskami zostawia jeden wpis `personal_data_viewed` w dzienniku
  audytu: kto, kiedy, który widok i identyfikatory osób. Same nazwiska nie trafiają do audytu.
- Przełącznik „Pokaż pseudonimy” w konsoli ukrywa nazwiska także osobom z uprawnieniem, np. na
  czas prezentacji. Wtedy wpisu w audycie nie ma, bo nazwiska nie zostały pokazane.
- Ochronę egzekwuje backend: endpoint wybiera pseudonim, a warstwa redakcji odpowiedzi
  zamienia nazwiska na pseudonimy, gdyby endpoint o tym zapomniał.

## Asystent Sentek

- Sentek pokazuje nazwiska na tych samych zasadach co konsola: tylko z `personal_data:view`,
  z wpisem `personal_data_viewed`, a przy włączonych pseudonimach tylko „Pracownik #N”.
- W audycie (`assistant_asked`) zapisujemy intencję, parametry, źródło rozpoznania, czas
  modelu i długość pytania. Treści pytania nie zapisujemy, bo menedżer może w niej wpisać
  nazwisko.
- Pytanie trafia wyłącznie do lokalnego modelu (zewnętrzny LLM nie jest tu używany) razem z
  nazwami działów i terminów ze słownika. Model zwraca tylko intencję; odpowiedź z danymi o
  urządzeniach i osobach buduje kod, więc tych danych model nie widzi.

## Pseudonimizacja zawsze

Bez względu na uprawnienia osoby, która eksportuje:

- raporty PDF i e-maile (wersja menedżera) nie zawierają nazwisk,
- dane wysyłane do zewnętrznego LLM (domyślnie wyłączonego) są zanonimizowane,
- dziennik audytu synchronizacji zawiera tylko liczby.

Numer pseudonimu jest stały dla osoby, więc raporty z różnych dni da się porównać.

## Retencja

- Osoba, której nie ma już w katalogu albo której konto wyłączono, jest oznaczana jako
  nieaktywna, a nie usuwana. Jej urządzenia zostają widoczne jako przypisane do kogoś, kto
  odszedł, żeby można było je przejąć.
- Po `PERSONAL_DATA_RETENTION_DAYS` dniach (domyślnie 90) codzienne zadanie zastępuje imię,
  nazwisko i stanowisko pseudonimem. Wpis `personal_data_erased` w audycie zawiera tylko
  liczbę osób.
- Kolejna synchronizacja z katalogu nie przywraca nazwiska osoby, która odeszła.

## Dane demonstracyjne

W repozytorium są wyłącznie fikcyjne osoby (`demo-lab/org/`). Przy `DEMO_MODE=true` konsola
pokazuje ich nazwiska z etykietą „dane demonstracyjne”. Repozytorium nie zawiera danych
prawdziwych osób ani wyników skanów prawdziwej infrastruktury.

## Prawa osób

Osoba może poprosić o dostęp do swoich danych albo ich sprostowanie. Źródłem danych jest
katalog organizacji, więc poprawka w AD albo Entra ID trafia do Sentinela przy najbliższej
synchronizacji. Usunięcie danych przed upływem retencji: administrator wyłącza konto w
katalogu i uruchamia zadanie retencji z krótszym okresem.
