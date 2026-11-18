#!/usr/bin/env bash
# Re-run the model experiment for all five models, then the log-only analysis.
# Safe to stop and restart: --resume skips finished runs. About 1-2.5 h per model on one 8 GB GPU.
set -euo pipefail
docker compose --profile llm up -d ollama
for m in qwen2.5:3b qwen2.5:7b llama3.1:8b mistral:7b gemma3:4b; do
  echo "== $m"; docker compose run --rm lab python -m obe.control --policy ollama --model "$m" --resume
done
for p in honest naive; do docker compose run --rm lab python -m obe.control --policy "$p"; done
docker compose run --rm lab python -m obe.control --policy insider --strategy all
docker compose run --rm lab python -m obe.control_eval
docker compose run --rm lab python -m obe.paper_tables
docker compose run --rm lab python -m obe.supplementary
