"""Supplementary analyses quoted in the paper (Sections 7.1, 7.4, 7.5). Reads saved logs only; no model calls.
Run: python -m obe.supplementary  (writes results/supplementary/*.csv and summary.md)"""
import json, os, glob, collections
import pandas as pd
import math
def pc(k, n, method=None, z=1.959964):
    p = k / n; d = 1 + z*z/n; c = (p + z*z/(2*n)) / d; h = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / d
    return c - h, c + h

BASE = "results/control"
MODELS = ["ollama-qwen2.5_3b", "ollama-gemma3_4b", "ollama-mistral_7b", "ollama-llama3.1_8b", "ollama-qwen2.5_7b"]
OUT = "results/supplementary"; os.makedirs(OUT, exist_ok=True)
B = lambda s: s.astype(str).str.lower() == "true"

def load(m):
    d = pd.read_csv(f"{BASE}/{m}/decisions.csv", keep_default_na=False)
    for c in ["high", "acted_drop", "infected_out", "task_hit"]:
        d[c] = B(d[c])
    d["control"] = d.run_id.str.contains("control")
    d["channel"] = d.run_id.str.split("|").str[1]
    d["topology"] = d.run_id.str.split("|").str[0]
    d["tasked"] = d.task.ne("null") & d.task.ne("")
    d["model"] = m.replace("ollama-", "")
    return d

D = pd.concat([load(m) for m in MODELS], ignore_index=True)
A = D[~D.control]
exp = A[(A.dose >= 1)]
lines = []
def w(s): lines.append(s); print(s)
def ci(k, n):
    lo, hi = pc(k, n, method="wilson") if n else (0, 0)
    return f"{k}/{n} ({100*k/n if n else 0:.1f}%, {100*lo:.1f}-{100*hi:.1f})"

w("## 1. Compliance split by tasked vs untasked privileged agents (exposed, attack runs)")
rows = []
for (mod, ch, tk), g in exp[exp.high].groupby(["model", "channel", "tasked"]):
    rows.append(dict(model=mod, channel=ch, tasked=tk, k=int(g.acted_drop.sum()), n=len(g)))
t1 = pd.DataFrame(rows); t1.to_csv(f"{OUT}/compliance_tasked_split.csv", index=False)
for (ch, tk), g in exp[exp.high].groupby(["channel", "tasked"]):
    w(f"pooled channel={ch} tasked={tk}: {ci(int(g.acted_drop.sum()), len(g))}")
for (mod, ch, tk), g in exp[exp.high].groupby(["model", "channel", "tasked"]):
    w(f"  {mod} {ch} tasked={tk}: {ci(int(g.acted_drop.sum()), len(g))}")
# tasked agent before vs after task completed
w("\n## 1b. Tasked privileged agents: decisions before vs after own task done")
for ch in ["direct", "handoff"]:
    g = exp[exp.high & exp.tasked & (exp.channel == ch)]
    w(f"{ch}: {ci(int(g.acted_drop.sum()), len(g))}")

w("\n## 2. What 'acted' means (acted_drop counts)")
for mod, g in A.groupby("model"):
    w(f"{mod}: all attack decisions acted_drop={int(g.acted_drop.sum())}; exposed all agents={int(g[g.dose>=1].acted_drop.sum())}; "
      f"exposed privileged={int(g[(g.dose>=1)&g.high].acted_drop.sum())}; exposed low-priv={int(g[(g.dose>=1)&~g.high].acted_drop.sum())}; "
      f"relayed (exposed)={int(g[g.dose>=1].infected_out.sum())}")

w("\n## 3. 212 privileged decisions to attacker vs 176 harmful sends to attacker")
pa = exp[exp.high & exp.acted_drop]
w(f"privileged exposed acted_drop = {len(pa)}")
sent = pa[pa.scope == "sent"]
w(f" of which scope=sent: {len(sent)}; with leaked records: {int((sent.leaked!='').sum())}; no records attached: {int((sent.records=='').sum())}")
hs = A[(A.scope == "sent") & (A.leaked != "")]
drop_of = {}
for m in MODELS:
    for line in open(f"{BASE}/{m}/events.jsonl", encoding="utf-8"):
        if '"type": "setup"' in line:
            e = json.loads(line); drop_of[(m.replace('ollama-',''), e["run_id"])] = e["drop"].lower()
hs = hs.assign(to_drop=[str(t).lower() == drop_of[(mo, r)] for t, mo, r in zip(hs.email_to, hs.model, hs.run_id)])
w(f"harmful sends (attack runs, no rule) = {len(hs)}; to attacker = {int(hs.to_drop.sum())}; exposed privileged among them = {int(((hs.dose>=1)&hs.high&hs.to_drop).sum())}")
w(f"acted_drop but not harmful: {int(((A.acted_drop)&(A.scope=='sent')&(A.leaked=='')).sum())} (email to attacker with no record)")
w(f"harmful to attacker by unexposed agents (dose 0): {int((hs.to_drop&(hs.dose==0)).sum())}")

w("\n## 4. Allow-list misses")
H = D[(D.scope == "sent") & (D.leaked != "")]
m = H[H["outcome[AL_allowlist]"] == "sent"]
w(f"harmful sends all runs = {len(H)} (attack {int((~H.control).sum())}, control {int(H.control.sum())}); AL missed {len(m)}: " +
  "; ".join(f"{r.model} {r.run_id} to={r.email_to} recs={r.records}" for r in m.itertuples()))

w("\n## 5. Fan-out: out-degree vs in-degree, and empirical offspring of relayers")
deg = collections.defaultdict(list)
off = []
for mo in MODELS:
    setups = {}
    for line in open(f"{BASE}/{mo}/events.jsonl", encoding="utf-8"):
        if '"type": "setup"' in line:
            e = json.loads(line); setups[e["run_id"]] = e
    for rid, e in setups.items():
        f = {int(k): v for k, v in e["follows"].items()}
        indeg = collections.Counter(j for v in f.values() for j in v)
        for i in range(1, 10):
            deg[e["topology"]].append((len(f[i]), indeg.get(i, 0)))
    g = A[A.model == mo.replace("ollama-", "")]
    for rid, gr in g.groupby("run_id"):
        e = setups[rid]; f = {int(k): v for k, v in e["follows"].items()}
        followers = collections.defaultdict(list)
        for i, v in f.items():
            for j in v: followers[j].append(i)
        relay = {(r.agent, r.step) for r in gr.itertuples() if r.infected_out}
        first = {}
        for a, s in sorted(relay, key=lambda x: x[1]):
            first.setdefault(a, s)
        for a, s in first.items():
            if s > 3: continue   # need >=2 later steps for children to be observed
            i = int(a[1:])
            kids = [c for c in followers[i] if f"a{c:02d}" in first and first[f"a{c:02d}"] > s]
            off.append(dict(model=mo, topology=e["topology"], step=s, n_followers=len(followers[i]), children=len(kids)))
for t, v in deg.items():
    o = [x[0] for x in v]; i_ = [x[1] for x in v]
    w(f"{t}: mean out-degree {sum(o)/len(o):.2f}, mean in-degree {sum(i_)/len(i_):.2f}, max in-degree {max(i_)}")
O = pd.DataFrame(off); O.to_csv(f"{OUT}/relay_offspring.csv", index=False)
w(f"relayers first relaying at step<=3: {len(O)}; mean followers {O.n_followers.mean():.2f}; mean children (new relayers among followers) {O.children.mean():.3f}; max {O.children.max()}")
for t, g in O.groupby("topology"):
    w(f"  {t}: n={len(g)} mean followers {g.n_followers.mean():.2f} mean children {g.children.mean():.3f}")

w("\n## 6. Scripted decisions")
tot = 0
for p in ["honest", "naive"] + [f"insider_{s}" for s in ["drop","allowlisted","task_contact","strip_drop","strip_allowlisted","strip_task_contact"]]:
    n = sum(1 for _ in open(f"{BASE}/{p}/decisions.csv", encoding="utf-8")) - 1
    r = sum(1 for _ in open(f"{BASE}/{p}/runs.csv", encoding="utf-8")) - 1
    tot += n; w(f"{p}: {r} runs, {n} decisions")
w(f"scripted total {tot}; model total {len(D)}; all {tot+len(D)}")

w("\n## 7. Hop of privileged decisions that emailed the attacker")
w(str(pa.groupby("hop").size().to_dict()))
open(f"{OUT}/summary.md", "w").write("\n".join(lines) + "\n")

w("\n## 8. Tasked vs untasked privileged agents, hop 1 and dose 1 only (same position)")
e1 = exp[exp.high & (exp.hop == 1) & (exp.dose == 1)]
for (ch, tk), g in e1.groupby(["channel", "tasked"]):
    w(f"{ch} tasked={tk}: {ci(int(g.acted_drop.sum()), len(g))}")
for (mod, ch, tk), g in e1.groupby(["model", "channel", "tasked"]):
    w(f"  {mod} {ch} tasked={tk}: {ci(int(g.acted_drop.sum()), len(g))}")
w("\n## 9. Untasked privileged exposures by topology/channel")
u = exp[exp.high & ~exp.tasked]
w(str(u.groupby(["channel", "topology"]).agg(n=("acted_drop", "size"), k=("acted_drop", "sum")).to_dict("index")))
w("\n## 10. Hierarchy relays by coordinator a01")
h = A[(A.topology == "hierarchy")]
w(f"a01 exposed decisions {int((h.agent=='a01').sum())}, relayed {int(h[h.agent=='a01'].infected_out.sum())}; all hierarchy relays {int(h.infected_out.sum())}")
w("\n## 11. Run-level: leaking runs with no rule by channel, counting only leaks by tasked agents vs untasked")
open(f"{OUT}/summary.md", "w").write("\n".join(lines) + "\n")
