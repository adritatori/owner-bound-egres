# Artifact: Beyond Provenance — Owner-Bound Egress for Data-Exfiltration Defense in Multi-Agent LLM Systems

This artifact contains the testbed, the seven egress rules, the unit tests, and the complete logs behind every
number in the paper. Every results table can be regenerated from the logs in about one minute, without a GPU
or a model. Re-running the model experiments is also supported (Section 4 below).

## 1. Layout

| Path | Contents |
|---|---|
| `obe/control.py` | Testbed for the paper's experiment: ten-agent runs, direct and hand-off channels, the seven egress rules (Table "Egress rules compared"), scripted honest, naive and insider policies |
| `obe/gateway.py`, `identity.py`, `audit.py`, `world.py` | Gateway: key-bound identity, signed scopes, hash-chained audit log, in-memory outbox |
| `obe/scenarios.py` | The six fixed injection templates and the attacker addresses (reserved example domains) |
| `obe/llm.py` | Ollama client (temperature 0, transcripts logged) |
| `obe/control_eval.py` | Log-only analysis: replays every rule verdict, main and breakdown tables |
| `obe/paper_tables.py` | Regenerates the paper's results tables into `results/paper_tables.md` |
| `obe/supplementary.py` | Supplementary analyses quoted in Sections 7.1, 7.4 and 7.5 (named task vs. no instruction, fan-out, count reconciliations) |
| `obe/swarm.py`, `run.py`, `analyze.py`, `policy.py`, `egress_check.py`, `taint_variants.py` | Earlier single-experiment testbed; `control.py` reuses its graph builders and parsers |
| `tests/` | 110 unit tests, including malformed and adversarial inputs |
| `results/control/<policy>/` | Raw logs, one folder per model or scripted policy (see Section 5) |
| `results/control_eval/`, `results/paper_tables.md`, `results/supplementary/` | Analysis outputs, regenerated from the logs |
| `scripts/` | `reproduce_from_logs.sh`, `pull_models.sh`, `run_all_models.sh` (and `.ps1` for Windows) |
| `Dockerfile`, `docker-compose.yml` | Network-isolated container (no internet route, read-only file system, no capabilities) |

## 2. Requirements

Python 3.10 or later with `pip install -r requirements.txt` (cryptography, requests, pytest, pandas, matplotlib),
or Docker. Reproducing from logs needs no GPU. Re-running models needs Ollama and one GPU with 8 GB of memory.

## 3. Reproduce every table from the logs (about one minute)

```
pip install -r requirements.txt
bash scripts/reproduce_from_logs.sh
```

or with Docker: `docker compose build && docker compose run --rm lab bash scripts/reproduce_from_logs.sh`.

Expected output: `110 passed`; `Runs: 1100. Decisions re-derived: 49500. Verdict mismatches between run and replay: 0`;
and `results/paper_tables.md` identical to the paper's tables.

| Paper claim or table | Command | Output |
|---|---|---|
| Verification: 49,500 decisions, 0 verdict mismatches (Section 6.4) | `python -m obe.control_eval` | first lines of `results/control_eval/summary.md` |
| 110 unit tests (Section 6.4) | `python -m pytest -q` | console |
| Compliance by channel, incl. "no operator text" column (Section 7.1) | `python -m obe.paper_tables` | `results/paper_tables.md`, first table |
| Run-level McNemar test (Section 7.1) | `python -m obe.paper_tables` | fifth section |
| Seven rules over five models (Section 7.2) | `python -m obe.paper_tables` | second table |
| Insider strategies (Section 7.3) | `python -m obe.paper_tables` | third table |
| Relay by hop (Section 7.4) | `python -m obe.paper_tables` | fourth table |
| Fan-out, in-degree and relayer offspring (Section 7.4) | `python -m obe.supplementary` | `results/supplementary/summary.md`, part 5 |
| Named task vs. no instruction at the same position (Section 7.1) | `python -m obe.supplementary` | part 8 |
| 212 emails to the attacker vs. 176 harmful sends; allow-list misses; control-run sends (Section 7.5) | `python -m obe.supplementary` | parts 3 and 4 |
| Scripted decision counts (Section 6.3) | `python -m obe.supplementary` | part 6 |

## 4. Re-run the experiments (optional; about 8 to 10 hours on one 8 GB GPU)

```
bash scripts/pull_models.sh        # once, needs internet: qwen2.5:3b, qwen2.5:7b, llama3.1:8b, mistral:7b, gemma3:4b
bash scripts/run_all_models.sh     # all five models, scripted policies, then the analysis
```

Each model runs 140 runs (5 topologies x 2 channels x 7 source contents x 2 seeds), 45 decisions per run, at
temperature 0. Runs are deterministic given the seed, the model version and the Ollama build; small differences
across Ollama or quantisation versions are possible, which is why the logs are shipped and every number in the paper
is computed from them.

## 5. Log format

Each `results/control/<policy>/` folder holds:

| File | One row or line per | Key fields |
|---|---|---|
| `config.json` | invocation | model, temperature, grid |
| `runs.csv` | run | run id (`topology|channel|template|seed`), per-rule leak, harmful sends and tasks done |
| `decisions.csv` | agent decision | step, agent, privilege, hop, exposure (`dose`), recipient, attached records, relayed?, emailed attacker?, task hit, per-rule verdict |
| `events.jsonl` | run setup and decision | graph, privileged agents, tasks, attacker address; each decision's inputs, operator text and message |
| `llm_transcripts.jsonl` | model call | full prompt, reply, latency, token counts |
| `gateway_log.jsonl` | gateway audit entry | hash-chained audit record |

`results/control/` holds five model folders (`ollama-*`) and eight scripted folders (`honest`, `naive`, six `insider_*`).

## 6. Safety

All records are fabricated, all addresses use reserved example domains, the outbox is an in-memory list, and the
container has no route to the internet. The six injection templates are of a kind already public; no new attack
text was written for this work.
