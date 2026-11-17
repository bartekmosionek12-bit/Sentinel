# Wyniki ewaluacji modeli (Etap 3)

Sprzęt: 4 rdzenie Intel Xeon 2,1 GHz (bez GPU), 16 GB RAM, Ollama 0.40.16, kontekst
4096 tokenów, temperatura 0,2. 20 przypadków × 3 poziomy = 60 odpowiedzi na model.
Szczegóły metodyki: [README.md](README.md). Surowe odpowiedzi: `results/v1/*.jsonl`.

## Rekomendacja

**Domyślny model: `qwen3-4b-q4km` (Qwen3 4B, Q4_K_M).** Częściej przechodzi automatyczną
kontrolę (80% wobec 62%), trzyma się limitów długości i formatu bez ponownych prób, a koszt na
CPU jest praktycznie taki sam. Bielik pisze naturalniejszą polszczyzną, ale dopisuje treści
spoza faktów (np. „w ciągu 7 dni”), formatowanie Markdown i dodatkowe akapity, myli się w
poleceniach (`opensl version`, `redis-server --verssion`) i w poziomie zarządczym rzadko
mieści się w 2 zdaniach. Odrzucona odpowiedź oznacza dla użytkownika wersję z szablonu, więc
liczy się przede wszystkim odsetek przechodzących odpowiedzi.

Bielik zostaje jako alternatywa (`LLM_MODEL=bielik-4.5b-q4km`, `./scripts/fetch_models.sh`)
dla zespołów, które wyżej cenią styl polszczyzny niż przewidywalność.

## Prompty v1 (pełny przebieg)

Wynik po ponownej ocenie zapisanych odpowiedzi poprawionym walidatorem (bez nowych wywołań
modelu): walidator przestał odrzucać nazwy przepisane dosłownie z faktów w znakach kodu,
np. `mod_proxy` albo `BN_mod_sqrt()` z opisu NVD. Literówki w poleceniach nadal są odrzucane.

| Metryka | Bielik 4.5B | Qwen3 4B |
|---|---:|---:|
| Przechodzi walidator | 61,7% | **80,0%** |
| – poziom zarządczy | 55% | **95%** |
| – poziom operacyjny | **95%** | 85% |
| – poziom techniczny | 35% | **60%** |
| Ponowne próby (błąd formy) | 12 z 60 | **0 z 60** |
| Odrzucenia za fakty (CVE, wersja, data, polecenie, link) | 25,0% | **20,0%** |
| Oczekiwane elementy w odpowiedzi | 85,5% | **91,9%** |
| Rozpoznany jako polski | **100%** | 96,7% |
| Odpowiedzi z formatowaniem Markdown | 22 z 60 | **0 z 60** |
| Mediana czasu do pierwszego tokenu | 5,5 s | 5,1 s |
| Mediana tokenów na sekundę | 7,1 | 7,1 |
| Mediana czasu odpowiedzi (90. percentyl) | 27 s (37 s) | 29 s (35 s) |
| Pamięć procesu modelu (RSS, tylko ten model wczytany) | **3,3 GB** | 3,6 GB |

Pamięć zmierzona osobno po wczytaniu jednego modelu; szczyt z przebiegu (5,0 i 7,6 GB)
obejmował chwilę, w której w pamięci były oba modele.

### Najczęstsze powody odrzucenia

- **Qwen3:** wylicza ostatnią podatną wersję z zakresu („poniżej 1.20.1” → „1.20.0”), czego
  nie ma w faktach (12 z 60). Czasem jest to poprawne, czasem nie (np. „15.2.9” dla
  PostgreSQL), więc walidator słusznie tego nie przepuszcza.
- **Bielik:** polecenia spoza faktów albo z literówką (11), za dużo zdań na poziomie
  zarządczym (8), wyliczone wersje (6).

## Ręczna ocena próbki (moja ocena, 16 odpowiedzi)

Próbka: CVE-2021-44228, CVE-2023-44487, CVE-2022-24735, CVE-2017-9798, poziom zarządczy i
operacyjny, oba modele. Skala 1–5.

| Kryterium | Bielik 4.5B | Qwen3 4B |
|---|---:|---:|
| Poprawność i naturalność polszczyzny | **4,5** | 3,5 |
| Wierność faktom (bez dopowiedzeń) | 3 | **4** |
| Trzymanie się formy dla odbiorcy | 2,5 | **4,5** |

Uwagi: Qwen3 robi błędy fleksji i kalki („atakantowi”, „niski ryzyko”, „streamów”). Bielik
pisze płynnie, ale dopisuje rady i terminy, których nie ma w faktach, i dodaje Markdown.
Oba modele streszczają zakres „od 2.0.1 włącznie poniżej 2.15.0” jako „od 2.0.1 do 2.15.0”,
czyli nieprecyzyjnie. Walidator tego nie wyłapuje, bo wszystkie liczby pochodzą z faktów:
sprawdza pochodzenie danych, nie sens zdania.

## Prompty v2

Na podstawie powodów odrzucenia prompty v2 dodają zasadę „zakresy wersji przepisuj
dokładnie, nie wyliczaj innych numerów” i zaostrzają zasady dla poleceń oraz liczby zdań.
Przebieg v2 dla obu modeli: wyniki zostaną dopisane poniżej.
