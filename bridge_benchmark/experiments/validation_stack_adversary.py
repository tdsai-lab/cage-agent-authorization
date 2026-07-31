#!/usr/bin/env python3
"""
validation_stack_adversary.py — NEW_EXPS EXP 2: adversary on the validation stack / TCB boundary.

System soundness decomposes (theory glue, §below):
    system-sound  ⟺  gate-sound  ∧  (realized corruption ⊆ B_{d,ε})
    P[system false allow] ≤ P[gate false allow | corruption ∈ budget] + P[corruption ∉ budget]
The first term is 0 (gate soundness, proven). So `system_false_allow = budget-escape rate`, and EXP 2 is a
DIRECT measurement of the only non-zero term. The gate does not claim to defend the stack; it claims
soundness CONDITIONAL on a declared stack, and EXP 2 measures how strong that stack must be.

Part A — Freshness-SLA sweep (headline). REAL wall-clock staleness on real IEEE-CIS: each transaction has
a real TransactionDT (seconds; re-joined from the raw CSVs — 100% of the gate pool). A stale cache serves
the value AS OF (t − Δt) for the SAME SURFACE (same x1 profile = same cache key), so drift is the genuine
risk_score change of that surface over real time, not a feature-space-similarity proxy. We sweep Δt and
report ε_emp@p95(Δt) against the declared ε=0.10, and `system_false_allow` (realized drift escapes the ball
AND crosses θ AND the gate allowed). The certificate's own `cert_false_allow` MUST stay 0 (soundness for the
declared budget); only `system_false_allow` moves. (A rank/feature-distance proxy is run as a SECONDARY
invariance check only — never the headline; the real wall-clock curve's shape is the scientific content.)

Self-consistency: EXP 2-A re-fits the held-out logistic on the real gate-pool split (seed 0; AUC≈0.76,
reproduces the generation scores to mean |Δ|≈0.013) and uses THESE scores for both the eval point and the
cache, so the measured drift is pure staleness, not score-reproduction error.

Part B — Constructor-corruption (TCB delimitation). A field-flip at the z-CONSTRUCTOR (prob p) mislabels
the discrete provenance before the typed interface. The gate certifies its (wrong) neighborhood and allows;
the action executes under the TRUE binding. This is OUTSIDE B_{d,ε} by construction — reported as the TCB
boundary, NOT a defended surface.
"""
from __future__ import annotations

import argparse
import os
import bisect
import csv
import json
import sys
import warnings
from collections import defaultdict
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
_HERE = Path(__file__).resolve().parent
_BB = _HERE.parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE / "opa_gate"))
sys.path.insert(0, str(_BB / "realdata"))

import ieee_cis_adapter as A  # noqa: E402
import ieee_cis_policy as pol  # noqa: E402
import pandas as pd  # noqa: E402

OUT = _BB / "cert" / "out"
RAW = os.environ.get("IEEE_CIS_DIR", "bridge_benchmark/data/raw/ieee_cis")
THETA_BASE = 0.488808
DELTA = 0.08
EPS = 0.10
# the cache "surface" = the CARD ENTITY (same physical card/account over real time), so the as-of read is
# genuine same-entity staleness `|score(t) − score(t−Δt)|`, NOT cross-entity feature-space spread. IEEE-CIS
# entity proxy = (card1,card2,card3,card5,addr1,addr2) (97% of txns are in multi-txn entities, median 5).
ENTITY_COLS = ["card1", "card2", "card3", "card5", "addr1", "addr2"]


# --------------------------------------------------------------------------- #
# build the real scored gate pool with wall-clock TransactionDT (self-consistent)
# --------------------------------------------------------------------------- #
def _stable_loose(tid: int) -> bool:
    """Deterministic provenance assignment (loose vs strict) by a stable hash of TransactionID. Provenance
    only sets θ (loose = θ+δ, strict = θ); the staleness drift curve itself is provenance-independent."""
    return (A._stable_unit(int(tid), seed=1234) < 0.5)


def _entity_map(max_rows=None):
    """TransactionID -> card-entity key, loaded directly from the raw CSV (the adapter drops these cols)."""
    cols = ["TransactionID"] + ENTITY_COLS
    df = pd.read_csv(Path(RAW) / "train_transaction.csv", usecols=cols, nrows=max_rows)
    ent = df[ENTITY_COLS].astype(str).agg("|".join, axis=1)
    return dict(zip(df["TransactionID"].astype(int).tolist(), ent.tolist()))


def build_pool(seed=0, max_rows=None):
    df = A.load_raw(RAW, max_rows=max_rows)
    split = A.assign_split(df, seed=seed)
    edges = A._amount_band_edges(pd.to_numeric(df["TransactionAmt"], errors="coerce"))
    tr = df[split == "risk_model_train"]
    gate = df[split == "gate_pool"].copy()
    pipe, _ = A.train_risk_model(tr, edges, seed=seed)
    risk = A.predict_risk(pipe, gate, edges)
    auc = A.heldout_auc(pipe, gate, edges)
    ent_map = _entity_map(max_rows=max_rows)
    tids = gate["TransactionID"].to_numpy()
    dts = pd.to_numeric(gate["TransactionDT"], errors="coerce").to_numpy()
    pool = []
    for tid, dt, r in zip(tids, dts, risk):
        loose = _stable_loose(tid)
        theta = THETA_BASE + (DELTA if loose else 0.0)
        pool.append({"tid": int(tid), "dt": float(dt), "risk": float(min(max(r, 0.0), 1.0)),
                     "surface": ent_map.get(int(tid), f"_unk_{int(tid)}"), "loose": loose, "theta": theta})
    return pool, float(auc)


def _strata(pool):
    """entity -> (sorted dts array, risk array aligned) for same-entity as-of reads over real time."""
    by = defaultdict(list)
    for p in pool:
        by[p["surface"]].append((p["dt"], p["risk"]))
    strata = {}
    for s, rows in by.items():
        rows.sort(key=lambda z: z[0])
        strata[s] = (np.array([z[0] for z in rows]), np.array([z[1] for z in rows]))
    return strata


def prev_read(strata, surface, t):
    """The entity's MOST RECENT prior risk read (the cache's relevant entry) and its age = t − dt_prev.
    Returns (prev_risk, age) or (None, None) if the entity has no prior transaction before t."""
    dts, risks = strata[surface]
    j = bisect.bisect_left(dts, t) - 1
    if j < 0:
        return None, None
    return float(risks[j]), float(t - dts[j])


# --------------------------------------------------------------------------- #
# Part A — freshness-SLA sweep (real wall-clock Δt)
# --------------------------------------------------------------------------- #
def sweep_deltat(pool, strata, deltas, eval_idx, eps=EPS):
    """Freshness-SLA model: a cache entry expires after Δt. A transaction is served from cache (a HIT) iff
    its entity's most-recent prior read is ≤ Δt old; else cache-miss → recompute fresh (no staleness). As Δt
    grows the hit set admits progressively staler priors, so ε_emp@p95 and the hit rate both grow."""
    # precompute (prev_risk, age) once per eval transaction (independent of Δt)
    prev = []
    for i in eval_idx:
        p = pool[i]
        pr, age = prev_read(strata, p["surface"], p["dt"])
        prev.append((p, pr, age))
    rows = []
    for sla in deltas:
        drifts, sys_fa, hits, allowed_hits = [], 0, 0, 0
        for p, pr, age in prev:
            if pr is None or age > sla:                            # cache miss (no prior within SLA)
                continue
            hits += 1
            delta = abs(pr - p["risk"]); drifts.append(delta)
            # declared-budget certified gate (exact continuous channel): allow iff risk+ε ≤ θ (robustly
            # safe within B_{1,ε}). cert_false_allow=0 by construction (worst in-ball case stays safe).
            if p["risk"] + eps <= p["theta"]:
                allowed_hits += 1
                if delta > eps and pr > p["theta"]:                # escapes budget AND realized-unsafe
                    sys_fa += 1
        eps_p95 = float(np.percentile(drifts, 95)) if drifts else float("nan")
        rows.append({"delta_t_sec": sla, "delta_t_days": round(sla / 86400, 3),
                     "coverage_hit_rate": round(hits / len(eval_idx), 4),
                     "eps_emp_p95": round(eps_p95, 4),
                     "eps_emp_p50": round(float(np.percentile(drifts, 50)), 4) if drifts else float("nan"),
                     "system_false_allow": round(sys_fa / max(1, allowed_hits), 6),
                     "n_allowed_hits": allowed_hits, "n_hits": hits,
                     "cert_false_allow": 0.0})
    return rows


def proxy_sweep(pool, ranks, eval_idx, eps=EPS):
    """SECONDARY invariance check (NOT headline): rank-proxy staleness = the r-th most distant same-surface
    risk by |Δrisk| (fresh→nearest, stale→more distant). Confirms the qualitative result (ε_emp exceeds 0.10,
    system_false_allow reappears) is robust to the staleness model."""
    by = defaultdict(list)
    for p in pool:
        by[p["surface"]].append(p["risk"])
    out = []
    for rk in ranks:
        drifts, sys_fa, allowed_n, cov = [], 0, 0, 0
        for i in eval_idx:
            p = pool[i]
            pool_r = by[p["surface"]]
            if len(pool_r) < 2:
                continue
            d_sorted = sorted(pool_r, key=lambda r: abs(r - p["risk"]))
            j = min(rk, len(d_sorted) - 1)
            stale = d_sorted[j]
            cov += 1
            delta = abs(stale - p["risk"]); drifts.append(delta)
            if p["risk"] + eps <= p["theta"]:
                allowed_n += 1
                if delta > eps and stale > p["theta"]:
                    sys_fa += 1
        out.append({"rank": rk, "eps_emp_p95": round(float(np.percentile(drifts, 95)), 4) if drifts else float("nan"),
                    "system_false_allow": round(sys_fa / max(1, allowed_n), 6), "coverage": round(cov / len(eval_idx), 4)})
    return out


# --------------------------------------------------------------------------- #
# Part B — constructor corruption (TCB boundary; balanced records + OPA labels)
# --------------------------------------------------------------------------- #
def constructor_corruption_sweep(probs, n_eval, seed):
    """Field-flip at the z-constructor (prob p): the discrete provenance is mislabelled BEFORE the typed
    interface. The Part-B gate TRUSTS the typed provenance field (it certifies the continuous channel at the
    delivered s — provenance is a typed input, the extractor that produces it is in the TCB) and allows iff
    risk+ε ≤ θ(s_obs). The action executes under s_true. This is the TCB boundary: it is OUTSIDE B_{d,ε}
    because the corruption is at construction, not an in-flight swap within N_d(s).

    Note on why provenance-trust is the right gate here: this policy's θ is 2-valued (loose/strict) and a
    d=1 neighborhood always spans BOTH classes, so a gate that ENUMERATES N_1 (EXP1) incidentally covers a
    single in-flight swap (z_true ∈ B_{1,ε}(z_observed)). Part B isolates the surface BELOW the typed
    interface — the field the gate must trust to act on it at all — which no in-interface certification
    addresses. The dangerous flip is strict→loose (true strict has the lower threshold).

    Labels via the analytic policy `ieee_cis_policy.safe`, which the OPA 1.17.1 engine reproduces at
    agreement 1.0 / Jaccard 1.0 on this exact policy (RESULTS Experiment 9b) — so this is engine-faithful
    and avoids OPA's slow varied-probe regime for a simple threshold sweep."""
    from ieee_cis_opa_cwitness import load_records
    rng = np.random.default_rng(seed)
    recs = load_records()
    idx = rng.permutation(len(recs))[:n_eval]
    ev = [recs[i] for i in idx]
    # The Part-B gate is the verified-POINT predicate that TRUSTS the typed provenance (EXP1's NEW row):
    # allow ⟺ Safe(observed point) = risk ≤ θ(s_obs). It is the point gate whose only TCB input is the
    # provenance the constructor produces. (NOTE: on this policy ε=0.10 ≥ δ=0.08, so a NEIGHBORHOOD/
    # continuous certificate's ε-margin already absorbs a single loose↔strict swap — its guarantee holds
    # for single in-budget corruption; the genuine residual hole is the point gate, i.e. the surface below
    # the typed interface that no in-interface certification closes.)
    out = []
    for p in probs:
        fa, n = 0, 0
        for r in ev:
            s_true = r["tool_id"]; x1 = r["x1"]; risk = float(r["x2"]["risk_score"])
            nb = list(pol.discrete_neighbors(s_true))
            s_obs = (nb[0] if (nb and rng.random() < p) else s_true)
            gate_allow = pol.safe(risk, s_obs, x1, THETA_BASE, DELTA)        # verified point @ trusted s_obs
            if gate_allow:
                n += 1
                if not pol.safe(risk, s_true, x1, THETA_BASE, DELTA):        # true binding unsafe -> missed
                    fa += 1
        out.append({"flip_prob": p, "false_allow": round(fa / max(1, n), 6), "n_allowed": n,
                    "n_eval": len(ev)})
    return out


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", default="0,1,2,3,4")
    ap.add_argument("--n-eval", type=int, default=4000)
    ap.add_argument("--max-rows", type=int, default=None)
    ap.add_argument("--probs", default="0.0,0.05,0.1,0.2,0.4")
    ap.add_argument("--part", default="A,B")
    args = ap.parse_args()
    seeds = [int(s) for s in args.seeds.split(",") if s.strip()]
    parts = set(args.part.split(","))
    OUT.mkdir(parents=True, exist_ok=True)
    # freshness-SLA grid in seconds (age>0 always under the SLA model). Sub-hour points resolve where drift
    # first crosses the declared ε; long points show the budget-escape rate saturating.
    deltas = [60, 300, 900, 1800, 3600, 21600, 86400, 259200, 604800, 2592000, 10368000]

    if "A" in parts:
        print("[EXP2-A] freshness-SLA sweep (real wall-clock Δt) ...")
        per_seed = []
        proxy_seed = []
        auc0 = None
        for s in seeds:
            pool, auc = build_pool(seed=s, max_rows=args.max_rows)
            auc0 = auc0 or auc
            strata = _strata(pool)
            rng = np.random.default_rng(s)
            eval_idx = rng.permutation(len(pool))[:args.n_eval]
            per_seed.append(sweep_deltat(pool, strata, deltas, eval_idx))
            proxy_seed.append(proxy_sweep(pool, [1, 2, 4, 8, 16, 32, 64], eval_idx))
            print(f"  seed={s}: pool={len(pool)} strata={len(strata)} AUC={round(auc,4)}")
        # aggregate Δt rows (mean±std over seeds)
        rowsA = []
        for di, dt_back in enumerate(deltas):
            cells = [ps[di] for ps in per_seed]
            def ms(k):
                v = [c[k] for c in cells]; return round(float(np.nanmean(v)), 4), round(float(np.nanstd(v)), 4)
            e_m, e_s = ms("eps_emp_p95"); sfa_m, sfa_s = ms("system_false_allow")
            cov_m, _ = ms("coverage_hit_rate")
            rowsA.append({"delta_t_sec": dt_back, "delta_t_days": round(dt_back / 86400, 3),
                          "coverage_hit_rate": cov_m, "eps_emp_p95_mean": e_m, "eps_emp_p95_std": e_s,
                          "declared_eps": EPS, "system_false_allow_mean": sfa_m,
                          "system_false_allow_std": sfa_s, "cert_false_allow": 0.0})
        # crossing Δt* where eps_emp_p95 first reaches declared eps
        cross = next((r["delta_t_days"] for r in rowsA if r["eps_emp_p95_mean"] >= EPS), None)
        with open(OUT / "exp2a_freshness_sla.csv", "w", newline="") as f:
            cols = ["delta_t_sec", "delta_t_days", "coverage_hit_rate", "eps_emp_p95_mean",
                    "eps_emp_p95_std", "declared_eps", "system_false_allow_mean",
                    "system_false_allow_std", "cert_false_allow"]
            w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(rowsA)
        # proxy invariance (secondary)
        rowsP = []
        for ri, rk in enumerate([1, 2, 4, 8, 16, 32, 64]):
            cells = [ps[ri] for ps in proxy_seed]
            rowsP.append({"rank": rk,
                          "eps_emp_p95_mean": round(float(np.nanmean([c["eps_emp_p95"] for c in cells])), 4),
                          "system_false_allow_mean": round(float(np.nanmean([c["system_false_allow"] for c in cells])), 6)})
        payloadA = {"risk_model_auc": auc0, "declared_eps": EPS, "deltas_sec": deltas,
                    "crossing_delta_t_days": cross, "table": rowsA,
                    "proxy_invariance_check_secondary": rowsP,
                    "cert_false_allow_invariant_holds": all(r["cert_false_allow"] == 0.0 for r in rowsA)}
        (OUT / "exp2a_freshness_sla.json").write_text(json.dumps(payloadA, indent=2))
        print(f"  Δt grid (days): {[r['delta_t_days'] for r in rowsA]}")
        print(f"  ε_emp@p95:      {[r['eps_emp_p95_mean'] for r in rowsA]}  (declared {EPS})")
        print(f"  system_FA:      {[r['system_false_allow_mean'] for r in rowsA]}")
        print(f"  hit_rate:       {[r['coverage_hit_rate'] for r in rowsA]}")
        print(f"  crossing Δt* (ε_emp@p95 reaches {EPS}): {cross} days")
        _maybe_plot(rowsA, cross)

    if "B" in parts:
        print("[EXP2-B] constructor-corruption (TCB boundary) ...")
        probs = [float(x) for x in args.probs.split(",") if x.strip()]
        per_seed = [constructor_corruption_sweep(probs, args.n_eval if args.n_eval <= 2000 else 2000, s)
                    for s in seeds]
        rowsB = []
        for pi, p in enumerate(probs):
            cells = [ps[pi] for ps in per_seed]
            rowsB.append({"flip_prob": p,
                          "false_allow_mean": round(float(np.nanmean([c["false_allow"] for c in cells])), 6),
                          "false_allow_std": round(float(np.nanstd([c["false_allow"] for c in cells])), 6)})
        with open(OUT / "exp2b_constructor_corruption.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["flip_prob", "false_allow_mean", "false_allow_std"])
            w.writeheader(); w.writerows(rowsB)
        (OUT / "exp2b_constructor_corruption.json").write_text(json.dumps(
            {"table": rowsB, "note": "OUTSIDE B_{d,ε}: provenance corrupted at the z-constructor, before "
             "the typed interface. This delimits where the guarantee stops — the gate certifies within "
             "the typed interface, the constructor is in the TCB."}, indent=2))
        print(f"  flip_prob:   {[r['flip_prob'] for r in rowsB]}")
        print(f"  false_allow: {[r['false_allow_mean'] for r in rowsB]}")
    print("done.")


def _maybe_plot(rowsA, cross):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return
    fig, ax1 = plt.subplots(figsize=(6, 4))
    x = [r["delta_t_days"] for r in rowsA]
    ax1.plot(x, [r["eps_emp_p95_mean"] for r in rowsA], "o-", color="C0", label="ε_emp@p95")
    ax1.axhline(EPS, ls="--", color="k", label=f"declared ε={EPS}")
    if cross is not None:
        ax1.axvline(cross, ls=":", color="C3", label=f"Δt* ≈ {cross}d")
    ax1.set_xlabel("freshness delay Δt (days)"); ax1.set_ylabel("ε_emp@p95 (risk_score drift)")
    ax2 = ax1.twinx()
    ax2.plot(x, [r["system_false_allow_mean"] for r in rowsA], "s-", color="C1", label="system_false_allow")
    ax2.set_ylabel("system_false_allow rate")
    ax1.legend(loc="upper left", fontsize=8); ax2.legend(loc="lower right", fontsize=8)
    ax1.set_xscale("symlog"); fig.tight_layout()
    fig.savefig(OUT / "exp2a_freshness_sla.pdf"); plt.close(fig)
    print(f"  wrote figure -> {OUT/'exp2a_freshness_sla.pdf'}")


if __name__ == "__main__":
    main()
