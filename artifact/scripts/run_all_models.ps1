# Windows equivalent of run_all_models.sh. Run from the artifact root.
$models = @("qwen2.5:3b", "qwen2.5:7b", "llama3.1:8b", "mistral:7b", "gemma3:4b")
docker compose --profile llm up -d ollama
foreach ($m in $models) {
    docker compose run --rm lab python -m obe.control --policy ollama --model $m --resume
    if ($LASTEXITCODE -ne 0) { Write-Host "Run failed for $m." -ForegroundColor Red; exit 1 }
}
foreach ($p in @("honest", "naive")) { docker compose run --rm lab python -m obe.control --policy $p }
docker compose run --rm lab python -m obe.control --policy insider --strategy all
docker compose run --rm lab python -m obe.control_eval
docker compose run --rm lab python -m obe.paper_tables
docker compose run --rm lab python -m obe.supplementary
