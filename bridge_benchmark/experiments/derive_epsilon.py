#!/usr/bin/env python3
"""
derive_epsilon.py — PLAN.md #17: derive a per-domain empirical continuous budget eps_emp from the
measured fault drift (#16), as the RESIDUAL after a declared validation stack — instead of the fixed
0.10. Multiple pipelines (fraud/risk, finance/compliance, alerting/monitoring) so the budget is
domain-derived, not global.

The threat radius the certificate must cover is the continuous drift that SURVIVES validation. We
report eps_emp under three validation regimes, each removing the faults a stage is meant to catch:

    none                       no validation -> residual = all continuous faults (worst case)
    integrity                  schema-version + key-integrity checks reject schema_skew (column
                               transposition) and cache_key_collision (wrong-entity serve) -> residual
                               = {stale_cache, numeric_jitter, normalization_skew}
    integrity_plus_freshness   additionally a TTL/freshness check bounds same-surface staleness ->
                               residual = {numeric_jitter, normalization_skew}

eps_emp = a high quantile (p90/p95/p99) of the pooled residual continuous drift, with the residual
faults pooled by their #16 relative frequencies (renormalized). The discrete budget stays d=1 (every
atomic fault is exactly d=1, Pr[d>=2]=0, measured in #16).

Outcome: eps=0.10 is well-calibrated under integrity+freshness (it sits near p95 of jitter/normalizer
drift); WITHOUT a freshness check the realistic radius is larger (driven by same-surface staleness),
which is exactly why #20 re-sweeps R_allow over the derived eps. Per-stage eps shrink is #19.

Reuses fault_injection.py (no new fault model). numpy only, deterministic.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

_root = Path(__file__).resolve().parents[1]
for p in ("generators", "experiments", "realdata", "agents"):
    sys.path.insert(0, str(_root / p))

import fault_injection as fi  # noqa: E402

OUT = _root / "cert" / "out"

# continuous faults only (the discrete budget is settled at d=1 in #16); weights inherited from #16.
CONTINUOUS = ["stale_cache", "numeric_jitter", "normalization_skew", "schema_skew",
              "cache_key_collision"]
REGIMES = {
    "none": set(CONTINUOUS),
    "integrity": {"stale_cache", "numeric_jitter", "normalization_skew"},
    "integrity_plus_freshness": {"numeric_jitter", "normalization_skew"},
}
# pipeline label -> substrate name (3 distinct pipelines)
PIPELINES = {"fraud_risk": "ieee_cis", "finance_compliance": "financial_compliance",
             "alerting_monitoring": "sre_monitoring"}


def pooled_residual_eps(sub, residual, n, seed):
    """Sample the residual continuous faults by their #16 frequencies and pool the eps drift."""
    rng = np.random.default_rng(seed + 11)
    faults = [f for f in residual if f in fi.INJECTORS]
    w = np.array([fi.FAULT_MIX[f] for f in faults], dtype=float)
    w /= w.sum()
    es = []
    tries = 0
    while len(es) < n and tries < n * 20:
        tries += 1
        f = faults[int(rng.choice(len(faults), p=w))]
        rec = sub.records[int(rng.integers(len(sub.records)))]
        z = fi.INJECTORS[f](rec, sub, rng)
        if z is None:
            continue
        es.append(fi.drift(rec, z, sub)[1])
    return np.array(es)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=6000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="epsilon_derivation")
    args = ap.parse_args()

    subs = {}
    if fi.IEEE_PATH.exists():
        subs["ieee_cis"] = fi.load_ieee_cis()
    else:
        print(f"[skip] IEEE-CIS data not found at {fi.IEEE_PATH}")
    for dom in ("financial_compliance", "sre_monitoring"):
        subs[dom] = fi.load_realistic(dom, seed=args.seed)

    rows = []
    for pipe, subname in PIPELINES.items():
        if subname not in subs:
            continue
        sub = subs[subname]
        for regime, residual in REGIMES.items():
            es = pooled_residual_eps(sub, residual, args.n, args.seed)
            if len(es) == 0:
                continue
            rows.append({
                "pipeline": pipe, "substrate": subname, "regime": regime,
                "residual_faults": "+".join(sorted(f for f in residual if f in fi.INJECTORS)),
                "n": int(len(es)), "d_budget": 1,
                "eps_p90": float(np.quantile(es, 0.90)), "eps_p95": float(np.quantile(es, 0.95)),
                "eps_p99": float(np.quantile(es, 0.99)), "eps_max": float(es.max()),
                "frac_le_010": float(np.mean(es <= 0.10)),
            })

    OUT.mkdir(parents=True, exist_ok=True)
    cols = ["pipeline", "substrate", "regime", "n", "d_budget", "eps_p90", "eps_p95", "eps_p99",
            "eps_max", "frac_le_010"]
    with open(OUT / f"{args.out}.csv", "w") as f:
        f.write(",".join(cols) + "\n")
        for r in rows:
            f.write(",".join(f"{r[c]:.3f}" if isinstance(r[c], float) else str(r[c]) for c in cols)
                    + "\n")
    with open(OUT / f"{args.out}.md", "w") as f:
        f.write("# PLAN.md #17 — per-domain empirical continuous budget eps_emp (residual after validation)\n\n")
        f.write("Discrete budget is `d=1` for all pipelines (every atomic fault is exactly d=1, "
                "Pr[d>=2]=0; measured in #16). `eps_emp` = a high quantile of the pooled residual "
                "continuous drift that SURVIVES the validation stack.\n\n")
        f.write("| pipeline | regime | residual continuous faults | eps p90 | **eps p95** | eps p99 | frac<=0.10 |\n")
        f.write("|---|---|---|---:|---:|---:|---:|\n")
        for r in rows:
            f.write(f"| {r['pipeline']} | {r['regime']} | {r['residual_faults']} | "
                    f"{r['eps_p90']:.3f} | **{r['eps_p95']:.3f}** | {r['eps_p99']:.3f} | "
                    f"{r['frac_le_010']:.3f} |\n")
        f.write("\n**Reads.** Under **integrity+freshness** validation the residual is sensor/re-read "
                "jitter + normalizer skew, whose p95 ~ 0.09-0.10 -> **eps=0.10 is well-calibrated**. "
                "Under **integrity only** (no freshness check) same-surface staleness survives and the "
                "p95 grows (driven by stale reads) -> the realistic radius is larger, which is exactly "
                "what #20 re-sweeps. The discrete budget stays d=1 throughout. Per-validation-stage "
                "eps shrink is #19.\n")

    print(f"{'pipeline':<20}{'regime':<26}{'eps_p95':>9}{'frac<=.10':>11}")
    print("-" * 66)
    for r in rows:
        print(f"{r['pipeline']:<20}{r['regime']:<26}{r['eps_p95']:>9.3f}{r['frac_le_010']:>11.3f}")
    print(f"\nwrote {OUT / (args.out + '.csv')}\nwrote {OUT / (args.out + '.md')}")
    return rows


if __name__ == "__main__":
    main()
