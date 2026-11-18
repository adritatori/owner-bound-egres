"""Regenerate the paper's results tables from the saved logs (no model calls).

  python -m obe.paper_tables        -> results/paper_tables.md

Table numbers follow the paper: compliance by channel, rules pooled over models,
insider strategies, relay by hop. Requires results/control_eval/main.csv
(python -m obe.control_eval) for the rule tables.
"""
import math
import os
import pandas as pd

BASE = os.path.join("results", "control")
MODELS = [("ollama-qwen2.5_3b", "Qwen2.5 3B"), ("ollama-gemma3_4b", "Gemma 3 4B"), ("ollama-mistral_7b", "Mistral 7B"),
          ("ollama-llama3.1_8b", "Llama 3.1 8B"), ("ollama-qwen2.5_7b", "Qwen2.5 7B")]
RULES = [("none", "none"), ("V0_privilege", "V0 privilege taint"), ("V2_content", "V2 content taint"),
         ("DP_dest_provenance", "DP destination provenance"), ("AL_allowlist", "AL allow-list"),
         ("DB_data_binding", "DB owner-bound egress"), ("DP+DB", "DP+DB")]
INSIDERS = [("drop", "its own outside address"), ("allowlisted", "another registered contact"),
            ("task_contact", "the contact of its own task"), ("strip_drop", "own address, retyped"),
            ("strip_allowlisted", "registered contact, retyped"), ("strip_task_contact", "task contact, retyped")]


def wilson(k, n, z=1.959964):
    if n == 0:
        return float("nan"), float("nan")
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def cell(k, n):
    lo, hi = wilson(k, n)
    return f"{k}/{n:,} ({100 * k / n:.1f}%, {100 * lo:.1f} to {100 * hi:.1f})" if n else "none exposed"


def load(tag):
    d = pd.read_csv(os.path.join(BASE, tag, "decisions.csv"), keep_default_na=False)
    for c in ["high", "acted_drop", "infected_out"]:
        d[c] = d[c].astype(str).str.lower() == "true"
    d["control"] = d.run_id.str.contains("control")
    d["channel"] = d.run_id.str.split("|").str[1]
    d["tasked"] = ~d.task.isin(["", "null"])
    return d


def kn(s):
    k, n = s.split(" ")[0].split("/")
    return int(k), int(n)


def main():
    out = []
    D = {name: load(tag) for tag, name in MODELS}

    out += ["## Compliance: privileged agents that emailed the attacker (exposed decisions, attack runs)", "",
            "| Model | Direct (named task) | Hand-off (grant) | No operator text (hop 1) |", "|---|---|---|---|"]
    tot = [[0, 0], [0, 0], [0, 0]]
    for name, d in D.items():
        e = d[~d.control & (d.dose >= 1) & d.high]
        parts = [e[e.channel == "direct"], e[e.channel == "handoff"],
                 e[(e.channel == "handoff") & ~e.tasked & (e.hop == 1) & (e.dose == 1)]]
        row = []
        for i, g in enumerate(parts):
            k, n = int(g.acted_drop.sum()), len(g)
            tot[i][0] += k; tot[i][1] += n; row.append(cell(k, n))
        out.append(f"| {name} | " + " | ".join(row) + " |")
    out += ["| All five | " + " | ".join(cell(k, n) for k, n in tot) + " |", ""]

    m = pd.read_csv(os.path.join("results", "control_eval", "main.csv"))
    llm = m[m.policy.str.startswith("llm")]
    out += ["## Seven rules over five models, pooled (worst single model in brackets)", "",
            "| Rule | Safe attack runs | Harmful sends held | Direct tasks done | Hand-off tasks done |", "|---|---|---|---|---|"]
    for key, label in RULES:
        g = llm[llm.rule == key]
        safe = g.safe_runs.sum(); att = g.attack_runs.sum(); worst = g.safe_runs.min()
        hb = [kn(s) for s in g.harmful_blocked]; ud = [kn(s) for s in g.useful_direct]; uh = [kn(s) for s in g.useful_handoff]
        sh = f"{safe}/{att}" + (f" [{worst}/120]" if worst < 120 else "")
        out.append(f"| {label} | {sh} | {sum(k for k, _ in hb)}/{sum(n for _, n in hb)} | "
                   f"{sum(k for k, _ in ud)}/{sum(n for _, n in ud)} | {sum(k for k, _ in uh)}/{sum(n for _, n in uh)} |")
    out.append("")

    out += ["## Insider strategies (safe runs out of 20)", "",
            "| Insider sends all records to | V0 | V2 | DP | AL | DB | DP+DB |", "|---|---|---|---|---|---|---|"]
    for key, label in INSIDERS:
        g = m[m.policy == f"insider_{key}"].set_index("rule")
        out.append(f"| {label} | " + " | ".join(str(int(g.loc[r, 'safe_runs'])) for r in
                   ["V0_privilege", "V2_content", "DP_dest_provenance", "AL_allowlist", "DB_data_binding", "DP+DB"]) + " |")
    out.append("")

    out += ["## Relay rate among exposed decisions, by hop", "", "| Model | Hop 1 | Hop 2 | Hop 3 |", "|---|---|---|---|"]
    for name, d in D.items():
        e = d[~d.control & (d.dose >= 1)]
        row = []
        for h in (1, 2, 3):
            g = e[e.hop == h]
            row.append(f"{int(g.infected_out.sum())}/{len(g):,}" + (f" ({100 * g.infected_out.mean():.1f}%)" if len(g) > 1 else "") if len(g) else "none exposed")
        out.append(f"| {name} | " + " | ".join(row) + " |")
    out.append("")

    out += ["## Run-level paired test, no egress rule (attack runs)", ""]
    pairs = {}
    for tag, name in MODELS:
        r = pd.read_csv(os.path.join(BASE, tag, "runs.csv"))
        r = r[~r.run_id.str.contains("control")]
        for row in r.itertuples():
            top, ch, tmpl, seed = row.run_id.split("|")
            pairs.setdefault((name, top, tmpl, seed), {})[ch] = str(getattr(row, "_%d" % (list(r.columns).index("leak[none]") + 1))).lower() == "true"
    dl = sum(v["direct"] for v in pairs.values()); hl = sum(v["handoff"] for v in pairs.values())
    b = sum(v["handoff"] and not v["direct"] for v in pairs.values()); c = sum(v["direct"] and not v["handoff"] for v in pairs.values())
    both = sum(v["handoff"] and v["direct"] for v in pairs.values())
    n = b + c; k = min(b, c)
    p = min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)
    out += [f"Leaking runs: direct {dl}/{len(pairs)}, hand-off {hl}/{len(pairs)}. Pairs: only hand-off {b}, only direct {c}, both {both}. "
            f"Exact McNemar p = {p:.2g}", ""]

    path = os.path.join("results", "paper_tables.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Paper tables (generated by obe/paper_tables.py from logs only)\n\n" + "\n".join(out))
    print("\n".join(out))
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
