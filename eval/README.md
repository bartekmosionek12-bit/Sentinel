# Ewaluacja modeli dla AI Explainera

Cel: wybrać domyślny lokalny model (`LLM_MODEL`) do wyjaśnień zagrożeń po polsku, na
sprzęcie z założeń projektu (4 rdzenie, 16 GB RAM, bez GPU). Model niczego w systemie nie
decyduje, więc ewaluacja mierzy tylko jakość i koszt tekstu.

## Kandydaci

| Nazwa w Ollamie | Model | Źródło | Kwantyzacja |
|---|---|---|---|
| `bielik-4.5b-q4km` | Bielik 4.5B v3.0 Instruct (SpeakLeash, ACK Cyfronet AGH), Apache 2.0 | `speakleash/Bielik-4.5B-v3.0-Instruct-GGUF`, plik fp16 | Q4_K_M wykonana lokalnie (`llama-quantize`), bo oficjalne repozytorium nie publikuje Q4_K_M |
| `qwen3-4b-q4km` | Qwen3 4B (Alibaba), Apache 2.0 | `Qwen/Qwen3-4B-GGUF` | Q4_K_M od producenta |

Rewizje i sumy SHA-256 plików są przypięte w `scripts/fetch_models.sh`, a szablony rozmowy
w `llm/Modelfile.*`. Qwen3 działa bez trybu rozumowania (`think: false` i pusty blok
`<think>` w szablonie), bo rozumowanie na CPU wydłuża odpowiedź kilkukrotnie.

## Przypadki

`cases.yaml`: 20 publicznie znanych podatności (Apache httpd, nginx, Redis, OpenSSH,
OpenSSL, PHP, PostgreSQL, Log4j, Spring, FortiOS), każda na trzech poziomach odbiorcy, czyli
60 odpowiedzi na model. Przypadki obejmują podatności z katalogu KEV i spoza niego, z wersją
naprawiającą i bez niej, z poleceniem sprawdzającym i bez niego. Fakty mają tę samą postać,
w jakiej składa je aplikacja; wartości EPSS są przykładowe.

## Metryki

- **Przechodzi walidator**: ten sam walidator, który działa w aplikacji, z jedną ponowną
  próbą przy błędzie formy (jak w aplikacji). Najważniejsza metryka: odpowiedź odrzucona
  oznacza, że użytkownik zobaczy wersję z szablonu.
- **Za pierwszym razem**: bez ponownej próby, czyli bez podwójnego czasu.
- **Odrzucenia za fakty**: CVE, wersja, data, polecenie albo link spoza faktów.
- **Oczekiwane elementy**: identyfikator CVE, wersja naprawiająca, informacja o atakach (KEV)
  i termin KEV tam, gdzie poziom odbiorcy tego wymaga.
- **Polszczyzna**: heurystyka walidatora i liczba angielskich wtrąceń; do tego ręczna ocena
  próbki w `RESULTS.md`.
- **Koszt na CPU**: czas do pierwszego tokenu, tokeny na sekundę, czas odpowiedzi i szczytowe
  RSS procesów Ollamy (model, kontekst 4096 tokenów).

## Uruchomienie

```bash
./scripts/fetch_models.sh --all
docker compose exec ollama ollama list
cd backend
uv run python ../eval/run_eval.py --ollama-url http://<adres-ollamy>:11434 \
    --model bielik-4.5b-q4km --model qwen3-4b-q4km --docker-container <kontener-ollamy>
```

Wyniki: `eval/results/<model>.jsonl` (wszystkie odpowiedzi) i `eval/results/summary.json`.
Pełny przebieg na 4 rdzeniach trwa około dwóch godzin.

## Raporty i plany agenta (Etap 5)

`run_eval_tasks.py` ocenia dwa kolejne zadania modelu na prawdziwym kodzie aplikacji i
fikcyjnych danych (SQLite w pamięci):

- `--task report` (`report_cases.yaml`, 4 scenariusze: czerwone, żółte, zielone i czerwone
  przy niskiej krytyczności). Światło liczy kod i przypadek sprawdza, że wyszło zgodnie z
  oczekiwaniem. Metryki: odpowiedź przechodzi walidator raportu (i za pierwszym razem), w
  tekście jest co najmniej jedna fraza zgodna ze światłem, brak fraz sprzecznych ze światłem
  (uspokajanie przy czerwonym, alarm przy zielonym), czas odpowiedzi.
- `--task plan` (`plan_cases.yaml`, 7 poleceń dla agenta). Metryki: plan z modelu (a nie z
  szablonu po błędzie JSON), oczekiwane narzędzia i cele w krokach dopuszczonych przez
  walidator, liczba kroków w granicy (bez nadgorliwości), narzędzia zbędne dla polecenia,
  kroki zablokowane przez politykę lub zakres.

```bash
cd backend
uv run python ../eval/run_eval_tasks.py --task report --model qwen3-4b-q4km
uv run python ../eval/run_eval_tasks.py --task plan --model qwen3-4b-q4km
uv run python ../eval/run_eval_tasks.py --task plan --model template   # punkt odniesienia
```

Punkt odniesienia bez modelu (plan z szablonu, 2026-11-20): 7/7 celów, 6/7 oczekiwanych
narzędzi, 0 kroków zablokowanych. Pomiar na Qwen3 4B wymaga Ollamy z modelem i jest
otwarty (nie mierzyłem go w tym środowisku).
