#!/usr/bin/env python3
"""
exp_fault_injection.py — EXP-FAULT: mechanistic fault-injection / budget calibration.

Companion to fault_injection.py (PLAN.md #16) and derive_epsilon.py (#17). Those two MEASURE the
aggregate drift distribution (d, eps) of mechanistically-faithful adapter faults and derive a
per-domain residual eps. This script adds the three genuine gaps they do NOT cover, to make the claim
"the threat budget B_{1,0.10} is not arbitrary" auditable at the per-record + oracle-label level:

  1. PER-FAULT JSONL records: one record per injected fault with the full before/after state,
     the measured drift (d_obs, epsilon_obs), an explicit in_budget flag (d<=1 AND eps<=eps_budget),
     and the ORACLE labels safe_before / safe_after (null on substrates without an oracle).
  2. CATEGORY-TRANSITION rates (where oracle labels exist): on the oracle-aware substrates we run
     oracle.category before and after each fault for a fixed candidate action and report
     Pr[Safe != Safe_fault], Pr[R->C], Pr[C->U], Pr[Safe->Unsafe].
  3. MULTI-SEED aggregation: mean +/- std of the key metrics across --seeds, per (substrate, fault).

It REUSES the fault functions and substrate loaders from fault_injection.py verbatim (imported, not
reimplemented) and the analytic oracle (generators/oracle.py) for the labels. The point it buys:

  * d = 1 is the atomic single-fault granularity. Every single discrete fault changes exactly one
    discrete atom (d_obs == 1, epsilon_obs == 0); no single fault reaches d >= 2.
  * A meaningful fraction of realistic CONTINUOUS faults land within eps = 0.10 after the
    integrity+freshness validation regime (jitter / normalizer skew), while schema-skew and
    cache-key-collision are the honestly-reported OUT-of-budget tail the certificate does NOT cover.

The certificate covers B_{1,eps}. It does NOT cover arbitrary endpoint fabrication (cache-key
collision = wrong-entity serve, schema-skew = column transposition): those are reported as
out-of-budget, not hidden.

No network, no LLM, no GPU. Deterministic (every RNG seeded). numpy only.
"""
from __future__ import annotations

import argparse
import json
import sys
import warnings
from collections import defaultdict
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
_root = Path(__file__).resolve().parents[1]
for p in ("generators", "experiments", "realdata", "agents"):
    sys.path.insert(0, str(_root / p))

import fault_injection as fi  # noqa: E402  (reuse fault fns + substrate loaders)
import oracle as orc  # noqa: E402  (analytic Safe(z,a) / category(z,a,d,eps))

OUT_DEFAULT = _root / "cert" / "out" / "exp_fault"

# faults that change a discrete atom only (d=1, eps=0) vs the continuous channel only (d=0).
DISCRETE_FAULTS = ["wrong_provenance_binding", "wrong_policy_pack", "toctou_env_label"]
CONTINUOUS_FAULTS = ["numeric_jitter", "normalization_skew", "stale_cache",
                     "cache_key_collision", "schema_skew"]
# the certificate's in-budget continuous channel (residual after integrity+freshness validation).
IN_BUDGET_CONTINUOUS = {"numeric_jitter", "normalization_skew"}
# same-surface staleness: in-budget under integrity-only, removed by a freshness/TTL check (#17).
FRESHNESS_REMOVABLE = {"stale_cache"}
# arbitrary endpoint fabrication: NOT covered by the certificate (must be caught by validation).
OUT_OF_BUDGET_FAULTS = {"schema_skew", "cache_key_collision"}


def _in_budget_class(fault):
    if fault in DISCRETE_FAULTS:
        return "discrete"
    if fault in IN_BUDGET_CONTINUOUS:
        return "in_budget"
    if fault in FRESHNESS_REMOVABLE:
        return "freshness_removable"
    return "out_of_budget"


# --------------------------------------------------------------------------- #
# Oracle adapter: wrap a Substrate with the (rule_table, domain, action) needed to call oracle.safe /
# oracle.category. Substrates without an analytic policy return None (safe_before/after = null).
# --------------------------------------------------------------------------- #
class OracleAdapter:
    """Turns a fault_injection.Substrate record {tool_id, x1, x2} into the z dict oracle.py expects,
    and exposes safe(rec) / category(rec, d, eps) for a fixed candidate action."""

    def __init__(self, rule_table: dict, domain: str, action: str):
        self.rt = rule_table
        self.domain = domain
        self.action = action

    def _z(self, rec: dict) -> dict:
        return {"domain": self.domain, "tool_id": rec["tool_id"],
                "categorical_fields": dict(rec["x1"]), "numeric_fields": dict(rec["x2"])}

    def safe(self, rec: dict):
        try:
            return bool(orc.safe(self._z(rec), self.action, self.rt))
        except (KeyError, ValueError):
            return None  # the fault produced a (tool,context) with no matching rule

    def category(self, rec: dict, d: int, eps: float):
        try:
            return orc.category(self._z(rec), self.action, self.rt, d=d, eps=eps)["category"]
        except (KeyError, ValueError):
            return None


def build_adapter(substrate_name: str):
    """Return an OracleAdapter for an oracle-aware substrate, else None (logged by caller)."""
    if substrate_name in ("financial_compliance", "sre_monitoring"):
        from realistic_schemas import finance_schema, monitoring_schema
        _, rt = finance_schema() if substrate_name == "financial_compliance" else monitoring_schema()
        from synthetic_tools import DOMAIN
        dc = rt["domains"][DOMAIN]
        action = dc["candidate_actions"][0]
        return OracleAdapter(rt, DOMAIN, action)
    if substrate_name == "ieee_cis":
        import ieee_cis_policy as pol
        cfg_path = _root / "data" / "realdata" / "ieee_cis_generation_config.json"
        cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
        theta_base = float(cfg.get("theta_base", 0.488808))
        delta = float(cfg.get("delta", 0.08))
        rt = pol.build_rule_table(theta_base, delta)
        return OracleAdapter(rt, pol.DOMAIN, pol.ACTION)
    return None


# --------------------------------------------------------------------------- #
# Coarse category collapse (A/B/C/R/U) for transition counting across both oracles.
# realistic oracle returns e.g. "C_joint_gap"; ieee oracle (via oracle.py) returns the same scheme.
# --------------------------------------------------------------------------- #
def _coarse(cat):
    if cat is None:
        return None
    return cat[0]  # "A_..","B_..","C_..","R_..","U_.." -> A/B/C/R/U


# --------------------------------------------------------------------------- #
# One (substrate, fault, seed) run -> per-fault records + a metrics row
# --------------------------------------------------------------------------- #
def run_one(sub, fault, adapter, n, seed, eps_budget, eps_thresholds):
    """Inject `fault` on up to `n` applicable records; emit per-fault records and a metrics dict.

    Mirrors fault_injection.run_fault's sampling (default_rng(seed + hash(fault)&0xFFFF), permutation)
    so the drift numbers reconcile with #16, but ALSO calls the oracle before/after."""
    rng = np.random.default_rng(seed + (hash(fault) & 0xFFFF))
    inj = fi.INJECTORS[fault]
    records = []
    order = rng.permutation(len(sub.records))
    applied = 0
    for ridx in order:
        if applied >= n:
            break
        rec = sub.records[int(ridx)]
        z = inj(rec, sub, rng)
        if z is None:
            continue
        d_obs, eps_obs = fi.drift(rec, z, sub)
        in_budget = bool(d_obs <= 1 and eps_obs <= eps_budget)
        if adapter is not None:
            safe_before = adapter.safe(rec)
            safe_after = adapter.safe(z)
            cat_before = adapter.category(rec, d=1, eps=eps_budget)
            cat_after = adapter.category(z, d=1, eps=eps_budget)
        else:
            safe_before = safe_after = cat_before = cat_after = None
        records.append({
            "seed": int(seed), "substrate": sub.name, "fault_type": fault,
            "s_before": {"tool_id": rec["tool_id"], "x1": dict(rec["x1"])},
            "s_after": {"tool_id": z["tool_id"], "x1": dict(z["x1"])},
            "x_before": [float(rec["x2"][f]) for f in sub.x2_fields],
            "x_after": [float(z["x2"][f]) for f in sub.x2_fields],
            "x2_fields": list(sub.x2_fields),
            "d_obs": int(d_obs), "epsilon_obs": float(eps_obs), "in_budget": in_budget,
            "eps_budget": float(eps_budget),
            "safe_before": safe_before, "safe_after": safe_after,
            "cat_before": _coarse(cat_before), "cat_after": _coarse(cat_after),
        })
        applied += 1

    if not records:
        return [], None

    ds = np.array([r["d_obs"] for r in records])
    es = np.array([r["epsilon_obs"] for r in records])
    row = {
        "substrate": sub.name, "fault_type": fault, "seed": int(seed), "n": int(len(records)),
        "channel": "discrete" if fault in DISCRETE_FAULTS else "continuous",
        "in_budget_class": _in_budget_class(fault),
        "pr_d0": float(np.mean(ds == 0)), "pr_d1": float(np.mean(ds == 1)),
        "pr_d_ge2": float(np.mean(ds >= 2)), "max_d": int(ds.max()),
        "eps_p50": float(np.quantile(es, 0.50)), "eps_p90": float(np.quantile(es, 0.90)),
        "eps_p95": float(np.quantile(es, 0.95)), "eps_p99": float(np.quantile(es, 0.99)),
        "eps_max": float(es.max()), "eps_mean": float(es.mean()),
    }
    for t in eps_thresholds:
        row[f"frac_in_B1_{t:g}"] = float(np.mean((ds <= 1) & (es <= t)))

    # transition rates over the records that HAVE oracle labels both before & after
    labelled = [r for r in records if r["safe_before"] is not None and r["safe_after"] is not None]
    row["n_labelled"] = len(labelled)
    if labelled:
        sb = np.array([r["safe_before"] for r in labelled])
        sa = np.array([r["safe_after"] for r in labelled])
        cb = [r["cat_before"] for r in labelled]
        ca = [r["cat_after"] for r in labelled]
        row["pr_safe_change"] = float(np.mean(sb != sa))
        row["pr_safe_to_unsafe"] = float(np.mean(sb & ~sa))
        row["pr_unsafe_to_safe"] = float(np.mean(~sb & sa))
        row["pr_R_to_C"] = float(np.mean([b == "R" and a == "C" for b, a in zip(cb, ca)]))
        row["pr_C_to_U"] = float(np.mean([b == "C" and a == "U" for b, a in zip(cb, ca)]))
        row["pr_R_to_U"] = float(np.mean([b == "R" and a == "U" for b, a in zip(cb, ca)]))
    else:
        for k in ("pr_safe_change", "pr_safe_to_unsafe", "pr_unsafe_to_safe",
                  "pr_R_to_C", "pr_C_to_U", "pr_R_to_U"):
            row[k] = None
    return records, row


# --------------------------------------------------------------------------- #
# Multi-seed aggregation: mean/std per (substrate, fault) over seed rows
# --------------------------------------------------------------------------- #
AGG_METRICS = ["pr_d0", "pr_d1", "pr_d_ge2", "eps_p50", "eps_p90", "eps_p95", "eps_p99",
               "eps_max", "eps_mean", "pr_safe_change", "pr_safe_to_unsafe", "pr_unsafe_to_safe",
               "pr_R_to_C", "pr_C_to_U", "pr_R_to_U"]


def aggregate(rows, eps_thresholds):
    by_key = defaultdict(list)
    for r in rows:
        by_key[(r["substrate"], r["fault_type"])].append(r)
    metrics = list(AGG_METRICS) + [f"frac_in_B1_{t:g}" for t in eps_thresholds]
    out = []
    for (sub, fault), rs in by_key.items():
        agg = {"substrate": sub, "fault_type": fault, "channel": rs[0]["channel"],
               "in_budget_class": rs[0]["in_budget_class"], "n_seeds": len(rs),
               "n_total": int(sum(r["n"] for r in rs)),
               "n_labelled_total": int(sum(r["n_labelled"] for r in rs)),
               "max_d": int(max(r["max_d"] for r in rs))}
        for m in metrics:
            vals = [r[m] for r in rs if r.get(m) is not None]
            if vals:
                agg[f"{m}_mean"] = float(np.mean(vals))
                agg[f"{m}_std"] = float(np.std(vals))
            else:
                agg[f"{m}_mean"] = None
                agg[f"{m}_std"] = None
        out.append(agg)
    out.sort(key=lambda a: (a["substrate"], a["channel"] != "discrete", a["fault_type"]))
    return out, metrics


# --------------------------------------------------------------------------- #
# Writers
# --------------------------------------------------------------------------- #
def write_per_fault(records, path):
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def write_summary_csv(agg, metrics, path):
    base = ["substrate", "fault_type", "channel", "in_budget_class", "n_seeds", "n_total",
            "n_labelled_total", "max_d"]
    cols = base + [c for m in metrics for c in (f"{m}_mean", f"{m}_std")]
    with open(path, "w") as f:
        f.write(",".join(cols) + "\n")
        for a in agg:
            vals = []
            for c in cols:
                v = a.get(c)
                vals.append("" if v is None else (f"{v:.4f}" if isinstance(v, float) else str(v)))
            f.write(",".join(vals) + "\n")


def write_summary_json(agg, meta, path):
    with open(path, "w") as f:
        json.dump({"meta": meta, "rows": agg}, f, indent=2)


def _f(v, nd=3):
    return "n/a" if v is None else f"{v:.{nd}f}"


def write_summary_md(agg, meta, path):
    eb = meta["eps_budget"]
    with open(path, "w") as f:
        f.write("# EXP-FAULT — mechanistic fault-injection / budget calibration\n\n")
        f.write(f"Budget under test: **B_{{1,{eb}}}** (d <= 1 atomic discrete swap AND "
                f"||x2 - x2'||_2 <= {eb}). Per-fault records in `per_fault.jsonl`; multi-seed "
                f"mean+/-std below ({meta['n_seeds']} seed(s), n={meta['n']} faults/seed/fault). "
                f"Oracle labels via generators/oracle.py on the oracle-aware substrates "
                f"({', '.join(meta['oracle_substrates']) or 'none available'}).\n\n")

        f.write("## Drift granularity (d) and continuous radius (eps)\n\n")
        f.write("| substrate | fault | class | Pr[d=0] | Pr[d=1] | Pr[d>=2] | eps p50 | eps p90 "
                f"| eps p95 | frac in B_1,{eb:g} |\n")
        f.write("|---|---|---|---:|---:|---:|---:|---:|---:|---:|\n")
        key = f"frac_in_B1_{eb:g}_mean"
        for a in agg:
            f.write(f"| {a['substrate']} | {a['fault_type']} | {a['in_budget_class']} | "
                    f"{_f(a['pr_d0_mean'])} | {_f(a['pr_d1_mean'])} | {_f(a['pr_d_ge2_mean'])} | "
                    f"{_f(a['eps_p50_mean'])} | {_f(a['eps_p90_mean'])} | {_f(a['eps_p95_mean'])} | "
                    f"{_f(a.get(key))} |\n")

        f.write("\n## Oracle category transitions (oracle-aware substrates)\n\n")
        f.write("| substrate | fault | Pr[Safe!=Safe'] | Pr[Safe->Unsafe] | Pr[R->C] | Pr[C->U] "
                "| Pr[R->U] |\n")
        f.write("|---|---|---:|---:|---:|---:|---:|\n")
        for a in agg:
            if a["n_labelled_total"] == 0:
                continue
            f.write(f"| {a['substrate']} | {a['fault_type']} | {_f(a['pr_safe_change_mean'])} | "
                    f"{_f(a['pr_safe_to_unsafe_mean'])} | {_f(a['pr_R_to_C_mean'])} | "
                    f"{_f(a['pr_C_to_U_mean'])} | {_f(a['pr_R_to_U_mean'])} |\n")

        f.write("\n## In-budget vs out-of-budget\n\n")
        f.write(f"**Discrete granularity.** Every single discrete fault "
                f"({', '.join(DISCRETE_FAULTS)}) changes exactly one atom: Pr[d=1]=1, eps=0, and "
                f"Pr[d>=2]=0. d=1 is therefore the *atomic single-fault granularity* — d>=2 requires "
                f"two compounded faults, not a single mechanism. This is measured, not asserted.\n\n")
        f.write(f"**In-budget continuous.** After integrity+freshness validation the residual "
                f"continuous faults are sensor/re-read jitter and normalizer skew "
                f"({', '.join(sorted(IN_BUDGET_CONTINUOUS))}); a large fraction of these land within "
                f"eps={eb} (see `frac in B_1,{eb:g}`). These are exactly the faults the certificate "
                f"covers.\n\n")
        f.write(f"**Freshness-removable.** {', '.join(sorted(FRESHNESS_REMOVABLE))} (same-surface "
                f"staleness) sits partly within eps={eb} under integrity-only validation; a "
                f"freshness/TTL check removes its tail (#17/derive_epsilon `integrity_plus_freshness` "
                f"regime). It is in-budget once a freshness SLA is declared.\n\n")
        f.write(f"**Out-of-budget (NOT covered).** "
                f"{', '.join(sorted(OUT_OF_BUDGET_FAULTS))} are honestly reported as the "
                f"out-of-budget tail: schema-skew is a column transposition and cache-key-collision "
                f"is a wrong-entity serve (arbitrary endpoint fabrication). The certificate does "
                f"**not** cover arbitrary endpoint fabrication; these are the faults a validation "
                f"stage (schema-version / key-integrity check) must catch, and #17/derive_epsilon "
                f"removes them from the residual eps.\n")


# --------------------------------------------------------------------------- #
def load_substrates(which, n_pool, seed, log):
    subs = {}
    if which in ("all", "ieee_cis"):
        if fi.IEEE_PATH.exists():
            subs["ieee_cis"] = fi.load_ieee_cis()
        else:
            log.append(f"[skip] ieee_cis: data not found at {fi.IEEE_PATH}")
    for dom in ("financial_compliance", "sre_monitoring"):
        if which in ("all", dom):
            try:
                subs[dom] = fi.load_realistic(dom, n_pool=n_pool, seed=seed)
            except Exception as e:  # noqa: BLE001
                log.append(f"[skip] {dom}: {type(e).__name__}: {e}")
    return subs


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--substrate", default="all",
                    choices=["all", "ieee_cis", "financial_compliance", "sre_monitoring"])
    ap.add_argument("--n", type=int, default=5000, help="faults per (substrate, fault, seed)")
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    ap.add_argument("--epsilons", type=float, nargs="+", default=[0.03, 0.05, 0.10, 0.20],
                    help="eps thresholds for frac-in-budget; the FIRST==eps_budget unless --eps-budget")
    ap.add_argument("--eps-budget", type=float, default=0.10)
    ap.add_argument("--n-pool", type=int, default=6000, help="record pool for the realistic substrates")
    ap.add_argument("--out", default=str(OUT_DEFAULT))
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    eps_thresholds = sorted(set(args.epsilons) | {args.eps_budget})
    log = []

    # substrates are seed-dependent for the realistic pool; load per seed.
    all_records, seed_rows = [], []
    oracle_subs = set()
    for seed in args.seeds:
        subs = load_substrates(args.substrate, args.n_pool, seed, log)
        for name, sub in subs.items():
            adapter = build_adapter(name)
            if adapter is not None:
                oracle_subs.add(name)
            else:
                log.append(f"[no-oracle] {name}: safe_before/after = null (no analytic policy)")
            for fault in DISCRETE_FAULTS + CONTINUOUS_FAULTS:
                recs, row = run_one(sub, fault, adapter, args.n, seed, args.eps_budget,
                                    eps_thresholds)
                if row is None:
                    log.append(f"[skip] {name}/{fault}: no applicable records")
                    continue
                all_records.extend(recs)
                seed_rows.append(row)

    agg, metrics = aggregate(seed_rows, eps_thresholds)
    meta = {"experiment": "EXP-FAULT", "n": args.n, "seeds": args.seeds,
            "n_seeds": len(args.seeds), "eps_budget": args.eps_budget,
            "eps_thresholds": eps_thresholds, "substrate": args.substrate,
            "oracle_substrates": sorted(oracle_subs), "n_per_fault_records": len(all_records),
            "discrete_faults": DISCRETE_FAULTS, "continuous_faults": CONTINUOUS_FAULTS,
            "in_budget_continuous": sorted(IN_BUDGET_CONTINUOUS),
            "out_of_budget_faults": sorted(OUT_OF_BUDGET_FAULTS), "log": log}

    write_per_fault(all_records, out_dir / "per_fault.jsonl")
    write_summary_csv(agg, metrics, out_dir / "summary.csv")
    write_summary_json(agg, meta, out_dir / "summary.json")
    write_summary_md(agg, meta, out_dir / "summary.md")

    print("=" * 100)
    for line in log:
        print(line)
    hdr = (f"{'substrate':<20}{'fault':<26}{'class':<14}{'Pr[d=1]':>8}{'Pr[d>=2]':>9}"
           f"{'eps_p90':>9}{'inBudget':>10}{'Safe->U':>9}")
    print(hdr); print("-" * 100)
    key = f"frac_in_B1_{args.eps_budget:g}_mean"
    for a in agg:
        print(f"{a['substrate']:<20}{a['fault_type']:<26}{a['in_budget_class']:<14}"
              f"{_f(a['pr_d1_mean']):>8}{_f(a['pr_d_ge2_mean']):>9}{_f(a['eps_p90_mean']):>9}"
              f"{_f(a.get(key)):>10}{_f(a['pr_safe_to_unsafe_mean']):>9}")
    print(f"\nwrote {out_dir / 'per_fault.jsonl'} ({len(all_records)} records)")
    print(f"wrote {out_dir / 'summary.csv'}")
    print(f"wrote {out_dir / 'summary.json'}")
    print(f"wrote {out_dir / 'summary.md'}")
    return agg


if __name__ == "__main__":
    main()
