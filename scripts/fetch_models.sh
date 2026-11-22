#!/usr/bin/env bash
# Pobiera lokalny model językowy do data/models/ (poza Gitem) i rejestruje go w Ollamie.
#
#   ./scripts/fetch_models.sh            model z LLM_MODEL w .env
#   ./scripts/fetch_models.sh --all      oba modele z ewaluacji (eval/RESULTS.md)
#
# Pliki pochodzą z oficjalnych repozytoriów producentów na Hugging Face, z przypiętej
# rewizji, i są sprawdzane sumą SHA-256. Kontener Ollamy nie ma dostępu do internetu:
# tylko wczytuje gotowe pliki z data/models/.
set -euo pipefail
cd "$(dirname "$0")/.."

HF=https://huggingface.co
DEST=data/models
mkdir -p "$DEST"

# nazwa w Ollamie | repozytorium | rewizja | plik | SHA-256
QWEN="qwen3-4b-q4km|Qwen/Qwen3-4B-GGUF|bc640142c66e1fdd12af0bd68f40445458f3869b|Qwen3-4B-Q4_K_M.gguf|7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5"
# Oficjalne repozytorium Bielika publikuje tylko fp16 i Q8_0, więc fp16 kwantyzujemy
# lokalnie do Q4_K_M narzędziem llama.cpp (przypięta wersja obrazu), a fp16 usuwamy.
BIELIK="bielik-4.5b-q4km|speakleash/Bielik-4.5B-v3.0-Instruct-GGUF|c80ffe0e154fab9f7af170993a16d6f8acc83903|Bielik-4.5B-v3.0-Instruct-fp16.gguf|1f62e00fda7a8a6ff718b3ef29995797c67df8ff4d5f34863b9b890890487cba"
# Tylko dla opcjonalnego Bielika: oficjalne repozytorium nie publikuje Q4_K_M, więc kwantyzujemy
# lokalnie. Ta ścieżka (obraz z GHCR) NIE jest zweryfikowana: kwantyzację sprawdziłem tylko
# llama.cpp uruchomionym poza Dockerem. Domyślny model (Qwen3 4B) jej nie używa.
LLAMA_CPP_IMAGE=ghcr.io/ggml-org/llama.cpp:full-b5350

download() {
  local repo=$1 rev=$2 file=$3 sha=$4
  if [ -f "$DEST/$file" ] && echo "$sha  $DEST/$file" | sha256sum -c --status; then
    echo "==> $file: już pobrany"
    return
  fi
  echo "==> Pobieram $file z $repo (rewizja ${rev:0:8})"
  curl -fL --retry 5 -C - -o "$DEST/$file.part" "$HF/$repo/resolve/$rev/$file"
  echo "$sha  $DEST/$file.part" | sha256sum -c --quiet
  mv "$DEST/$file.part" "$DEST/$file"
}

register() {
  local name=$1 modelfile=$2
  echo "==> Rejestruję $name w Ollamie"
  docker compose --profile llm up -d ollama >/dev/null
  docker compose --profile llm exec -T ollama ollama create "$name" -f "/modelfiles/$modelfile"
}

fetch() {
  IFS='|' read -r name repo rev file sha <<<"$1"
  case "$name" in
    qwen3-4b-q4km)
      download "$repo" "$rev" "$file" "$sha"
      register "$name" Modelfile.qwen3-4b
      ;;
    bielik-4.5b-q4km)
      local quantized=Bielik-4.5B-v3.0-Instruct-Q4_K_M.gguf
      if [ ! -f "$DEST/$quantized" ]; then
        download "$repo" "$rev" "$file" "$sha"
        echo "==> Kwantyzacja do Q4_K_M ($LLAMA_CPP_IMAGE)"
        docker run --rm --network none -v "$PWD/$DEST:/models" \
          --entrypoint /app/llama-quantize "$LLAMA_CPP_IMAGE" \
          "/models/$file" "/models/$quantized.part" Q4_K_M
        mv "$DEST/$quantized.part" "$DEST/$quantized"
        rm -f "$DEST/$file"
      fi
      register "$name" Modelfile.bielik-4.5b
      ;;
  esac
}

wanted=""
if [ "${1:-}" = "--all" ]; then
  wanted="$BIELIK $QWEN"
else
  model=$(grep -E '^LLM_MODEL=' .env 2>/dev/null | cut -d= -f2- | tr -d '"' || true)
  case "$model" in
    qwen3-4b-q4km) wanted=$QWEN ;;
    bielik-4.5b-q4km) wanted=$BIELIK ;;
    "") echo "LLM_MODEL w .env jest pusty. Domyślny model: qwen3-4b-q4km (patrz .env.example); albo użyj --all." >&2; exit 1 ;;
    *) echo "Nieznany model $model. Dostępne: qwen3-4b-q4km, bielik-4.5b-q4km." >&2; exit 1 ;;
  esac
fi
for entry in $wanted; do fetch "$entry"; done
echo "Gotowe. Modele w Ollamie:"
docker compose --profile llm exec -T ollama ollama list
