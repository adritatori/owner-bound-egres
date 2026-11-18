#!/usr/bin/env bash
# Regenerate every table in the paper from the shipped logs. No model, no GPU, about one minute.
set -euo pipefail
cd "$(dirname "$0")/.."
python -m pytest -q -p no:cacheprovider        # 110 tests
python -m obe.control_eval                      # verdict replay (expects 49,500 decisions, 0 mismatches)
python -m obe.paper_tables                      # results/paper_tables.md
python -m obe.supplementary                     # results/supplementary/summary.md
