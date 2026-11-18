#!/usr/bin/env bash
# Download the five models once into the shared Docker volume (needs internet once).
set -euo pipefail
for m in qwen2.5:3b qwen2.5:7b llama3.1:8b mistral:7b gemma3:4b; do
  echo "== pulling $m"; MODEL="$m" docker compose --profile pull run --rm ollama-pull
done
