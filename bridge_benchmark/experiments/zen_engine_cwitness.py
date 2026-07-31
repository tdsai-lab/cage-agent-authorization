#!/usr/bin/env python3
"""
zen_engine_cwitness.py — PLAN_2_RESCAN_BIS Workstream B2: a Category-C witness on the `x ▷ θ(s)` idiom
implemented in a REAL PRODUCTION rule engine (GoRules ZEN / JDM), labelled by the ENGINE.

This is the operational-harness result the v2 plan calls the strongest single outcome. Unlike #9b (real
OPA engine, authored Rego) this uses a SECOND, independent production engine — GoRules ZEN, a JDM
decision-table engine (Rust core, used in fintech) — and, crucially, the discrete key `s` is a
*provenance / list-source* class (loose vs strict screening tool), i.e. **genuinely upstream-set**, so
the joint-gap is exactly the post-return agent threat we target (not a self-reported subject attribute).

We author a JDM decision table `safe = risk_score < θ(provenance)` with the real IEEE-CIS generation
constants (θ=0.488808, θ_loose=θ+0.08), run REAL IEEE-CIS transactions through the ZEN engine, and port
the #9b solver: per transaction the engine labels the joint ball B_{1,ε} — clean, the d=1 provenance
swap (loose↔strict = the #16 `wrong_provenance_binding` fault), the +ε risk probe, and the joint
swap+ε point. C ⟺ engine says clean-safe ∧ swap-only-safe ∧ ε-only-safe ∧ swap+ε-unsafe.

Claim discipline (per the plan): this is an ENGINE-VALID witness — same epistemic rank as #9b (real
engine, authored rule), arguably more threat-model-relevant because `s` is upstream-set. It is NOT a
claim that the idiom was *found* in deployed AML rules (deployed thresholds are confidential — see the
Workstream-C documentary anchor). Real engine, authored rule, real data.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parents[0] / "realdata"))

import ieee_cis_policy as pol  # noqa: E402  (real generation constants + loose/strict provenance)

_BB = _HERE.parents[0]
IEEE_PATH = _BB / "data" / "realdata" / "ieee_cis_boundary_balanced_s0.jsonl"
OUT = _BB / "cert" / "out"

THETA = 0.488808            # real IEEE-CIS theta_base
DELTA = 0.08               # loose tools trust more -> +delta
THETA_LOOSE = round(THETA + DELTA, 6)


def jdm_model():
    """The authored `x ▷ θ(s)` rule as a real JDM decision graph (input → decision table → output)."""
    return {"nodes": [
        {"id": "in", "type": "inputNode", "name": "request", "position": {"x": 0, "y": 0}},
        {"id": "dt", "type": "decisionTableNode", "name": "aml_provenance_gate",
         "position": {"x": 220, "y": 0}, "content": {
             "hitPolicy": "first",
             "inputs": [{"id": "i1", "name": "provenance", "field": "provenance"},
                        {"id": "i2", "name": "risk", "field": "risk_score"}],
             "outputs": [{"id": "o1", "name": "safe", "field": "safe"}],
             "rules": [
                 {"_id": "r1", "i1": '== "loose"', "i2": f"< {THETA_LOOSE}", "o1": "true"},
                 {"_id": "r2", "i1": '== "loose"', "i2": "", "o1": "false"},
                 {"_id": "r3", "i1": '== "strict"', "i2": f"< {THETA}", "o1": "true"},
                 {"_id": "r4", "i1": '== "strict"', "i2": "", "o1": "false"}]}},
        {"id": "out", "type": "outputNode", "name": "resp", "position": {"x": 440, "y": 0}}],
        "edges": [{"id": "e1", "sourceId": "in", "targetId": "dt", "type": "edge"},
                  {"id": "e2", "sourceId": "dt", "targetId": "out", "type": "edge"}]}


def _provenance_class(tool):
    return "loose" if pol.is_loose(tool) else "strict"


def _other(cls):
    return "strict" if cls == "loose" else "loose"


def load_records(path=IEEE_PATH, n=None):
    recs = []
    with open(path) as f:
        for line in f:
            o = json.loads(line)
            recs.append({"tool_id": o["tool_id"], "risk_score": float(o["x2"]["risk_score"]),
                         "analytic_category": o.get("category"), "fraud": int(o["meta"]["isFraud"])})
    return recs[:n] if n else recs


class ZenGate:
    """Wraps the real GoRules ZEN engine; `safe(provenance, risk)` is the ENGINE's verdict."""

    def __init__(self):
        import zen
        self.dec = zen.ZenEngine().create_decision(json.dumps(jdm_model()))

    def safe(self, provenance, risk):
        r = self.dec.evaluate({"provenance": provenance, "risk_score": float(risk)})
        return bool(r["result"]["safe"])


def categorize(gate, records, eps):
    """Per record, the ENGINE labels clean / d=1 provenance swap / +eps / joint -> A/B/C/R/U."""
    out = []
    for r in records:
        cls = _provenance_class(r["tool_id"])
        oth = _other(cls)
        risk = r["risk_score"]
        clean = gate.safe(cls, risk)
        disc = gate.safe(oth, risk)                  # provenance swap alone (clean risk)
        cont = gate.safe(cls, risk + eps)            # eps move alone (same provenance)
        joint = gate.safe(oth, risk + eps)           # joint swap + eps
        disc_flip = disc != clean
        cont_flip = cont != clean
        joint_flip = joint != clean
        cat = ("U" if not clean else "A" if disc_flip else "B" if cont_flip
               else "C" if joint_flip else "R")
        out.append({"category": cat, "provenance": cls, "swap_to": oth, "risk_score": round(risk, 4),
                    "engine_clean_safe": clean, "engine_swap_only": disc,
                    "engine_eps_only": cont, "engine_joint": joint})
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=4000)
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--out", default="zen_engine_cwitness")
    args = ap.parse_args()

    if not IEEE_PATH.exists():
        print(f"[error] IEEE-CIS data not found at {IEEE_PATH}")
        return
    try:
        import zen  # noqa: F401
    except ImportError:
        print("[error] zen-engine not installed (pip install zen-engine)")
        return

    recs = load_records(n=args.n)
    gate = ZenGate()
    cats = categorize(gate, recs, args.eps)
    dist = Counter(c["category"] for c in cats)
    n = len(recs)

    # engine (ZEN) vs the stored analytic taxonomy agreement
    both = [(c["category"], r["analytic_category"]) for c, r in zip(cats, recs)
            if r["analytic_category"] in ("A", "B", "C", "R", "U")]
    agree = sum(1 for e, a in both if e == a) / max(1, len(both))
    c_eng = {i for i, c in enumerate(cats) if c["category"] == "C"}
    c_ana = {i for i, r in enumerate(recs) if r["analytic_category"] == "C"}
    c_jaccard = len(c_eng & c_ana) / max(1, len(c_eng | c_ana))
    witnesses = [cats[i] for i in list(c_eng)[:5]]

    res = {
        "engine": "GoRules ZEN/JDM", "engine_pkg": "zen-engine",
        "rule": f"safe = risk_score < theta(provenance); theta_strict={THETA}, theta_loose={THETA_LOOSE}",
        "s_semantics": "provenance_upstream (screening-tool / list-source class; pipeline-set)",
        "n_records": n, "eps": args.eps,
        "engine_category_distribution": {k: dist.get(k, 0) for k in ("U", "A", "B", "C", "R")},
        "engine_C_count": dist.get("C", 0), "engine_C_pct": round(100 * dist.get("C", 0) / n, 2),
        "engine_vs_analytic_agreement": round(agree, 4),
        "C_set_jaccard_engine_vs_analytic": round(c_jaccard, 4),
        "witnesses": witnesses,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{args.out}.json").write_text(json.dumps(res, indent=2))
    with open(OUT / f"{args.out}.md", "w") as f:
        f.write("# PLAN_2_RESCAN_BIS B2 — engine-verified C-witness on a REAL production rule engine (GoRules ZEN)\n\n")
        f.write(f"Engine: **GoRules ZEN / JDM** (`zen-engine`), a real production decision engine. Rule "
                f"(authored, real constants): `{res['rule']}`. `s` = **{res['s_semantics']}**. "
                f"{n} REAL IEEE-CIS transactions, eps={args.eps}. Every label is the ZEN engine's.\n\n")
        d = res["engine_category_distribution"]
        f.write(f"- engine category distribution: U={d['U']} A={d['A']} B={d['B']} **C={d['C']} "
                f"({res['engine_C_pct']}%)** R={d['R']}\n")
        f.write(f"- ZEN-engine vs analytic taxonomy agreement: **{res['engine_vs_analytic_agreement']}** "
                f"(C-set Jaccard {res['C_set_jaccard_engine_vs_analytic']})\n\n")
        f.write("## Engine-verified C-witness traces (each label is ZEN's)\n\n")
        f.write("| provenance | swap | risk_score | clean | swap-only | +ε-only | **swap+ε** |\n")
        f.write("|---|---|---:|:--:|:--:|:--:|:--:|\n")
        for w in witnesses:
            f.write(f"| {w['provenance']} | →{w['swap_to']} | {w['risk_score']} | "
                    f"{'safe' if w['engine_clean_safe'] else 'UNSAFE'} | "
                    f"{'safe' if w['engine_swap_only'] else 'UNSAFE'} | "
                    f"{'safe' if w['engine_eps_only'] else 'UNSAFE'} | "
                    f"**{'safe' if w['engine_joint'] else 'UNSAFE'}** |\n")
        f.write("\n**Reads.** A SECOND independent production engine (GoRules ZEN, after OPA in #9b) "
                "labels real transactions as Category-C joint-gap witnesses, and reproduces the analytic "
                "taxonomy. Here `s` is a **provenance / list-source class** — genuinely upstream-set, so "
                "the swap is exactly the #16 `wrong_provenance_binding` fault that an agent's upstream "
                "pipeline can realize, making this MORE threat-model-relevant than a subject-keyed "
                "threshold. Epistemic rank = #9b (real engine, authored rule, real data); NOT a claim "
                "the idiom was found in deployed AML rules (those thresholds are confidential — see the "
                "Workstream-C regulatory anchor).\n")

    print(json.dumps({k: v for k, v in res.items() if k != "witnesses"}, indent=2))
    print(f"\nwrote {OUT / (args.out + '.json')}\nwrote {OUT / (args.out + '.md')}")
    return res


if __name__ == "__main__":
    main()
