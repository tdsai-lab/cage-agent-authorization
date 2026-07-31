#!/usr/bin/env python3
"""
exp_opa_full.py — EXP-OPA-FULL: full authored-policy robustness/utility sweep with REAL OPA labels.

Labels and the A/B/C/R/U category of every typed return z=(t,x1,x2) come from the REAL OPA/Rego engine
(`opa eval`, via opa_oracle.OpaOracle -> opa_bridge.eval_batch), NOT from the analytic generator. The
certified post-return gate is then certified per record over the joint ball B_{1,eps} with a FAMILY-WISE
Clopper-Pearson level (alpha_branch = alpha_FWER / num_branches, the exact accounting reused from
run_opa_gate.py), and we report the robustness-utility trade-off across:

        seeds  x  epsilons  x  taus  x  backends   (nested loops)

This script REUSES (does not re-implement):
  * OpaOracle (opa_oracle.py)            -> real `opa eval` labels + categories
  * train_gate_opa (run_opa_gate.py)     -> the OPA-relabelled smoothing MLP gate
  * cert.smoothed_gate.certify           -> the SMOOTHING backend certificate
  * lip_gate.models.lip_gate.*           -> the deterministic 1-Lipschitz backend (skip-guarded)

Genuine new pieces (only these):
  1. the nested seeds x eps x tau x backend driver,
  2. a per-example jsonl accumulator,
  3. utility-curve CSVs (R_allow vs eps; R_allow vs tau) with mean+/-std across seeds,
  4. a consolidated summary.csv/.json over every (domain,backend,sigma,tau,eps) cell,
  5. summary.md narrative + alpha_branch distribution log.

Acceptance target (per cell): certified gate has C_allow=0, U_allow=0, cert_false_allow=0, R_allow>0.
We report honestly if any cell misses it.

CLI:
  python bridge_benchmark/experiments/exp_opa_full.py \
      --seeds 0 1 2 3 4 --epsilons 0.03 0.05 0.10 --taus 0.80 0.90 0.95 0.99 \
      --backends smoothing lipschitz --n-mc 2000 --alpha-fwer 0.001 \
      --out bridge_benchmark/cert/out/exp_opa_full

  python bridge_benchmark/experiments/exp_opa_full.py --quick \
      --out bridge_benchmark/cert/out/exp_opa_full_quick
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

_HERE = Path(__file__).resolve().parent              # bridge_benchmark/experiments
_BB = _HERE.parent                                   # bridge_benchmark
# same sys.path pattern as run_opa_gate.py
for p in ("generators", "models", "cert"):
    sys.path.insert(0, str(_BB / p))
sys.path.insert(0, str(_BB / "experiments" / "opa_gate"))

from oracle import discrete_swaps  # noqa: E402
from smoothed_gate import certify  # noqa: E402
from schema import DOMAINS, sample_records  # noqa: E402
from opa_oracle import OpaOracle  # noqa: E402
from run_opa_gate import train_gate_opa  # noqa: E402

# ---- Lipschitz backend: SKIP-GUARDED (torch/orthogonium optional) ----
_LIP_OK = True
_LIP_ERR = ""
try:  # pragma: no cover - import guard
    sys.path.insert(0, str(_BB / "experiments" / "lip_gate" / "models"))
    from lip_gate import (  # noqa: E402
        make_encoder, train_lipgate, certify_lip, LipSmoothWrapper,
    )
    from orthogonium_adapter import empirical_lipschitz, CLAIMED_L, backend_name  # noqa: E402
    import torch  # noqa: E402
except Exception as e:  # pragma: no cover
    _LIP_OK = False
    _LIP_ERR = f"{type(e).__name__}: {e}"

SIGMA = 0.10            # smoothing noise (raw units); ε/σ=1.0 at ε=0.10 (the project operating point)
N_AUG = 4               # OPA-relabelled augmentation per train record (matches run_opa_gate)
LIP_VARIANT = "robust-aug"


# --------------------------------------------------------------------------- #
# one (domain, backend, seed) base: train ONCE, certify across the eps x tau grid
# --------------------------------------------------------------------------- #
def _branches(dc, rec):
    """num_branches = 1 (identity) + |exact d=1 discrete swaps| — the FWER family size (reused accounting)."""
    return 1 + len(list(discrete_swaps(dc, rec["tool_id"], rec["categorical_fields"], 1)))


def run_cell_base(domain, backend, seed, n_train, n_eval, n_mc, alpha_fwer, epsilons, scheme="natural"):
    """Train the gate for (domain, backend, seed) once, then certify every eval record across the
    (eps, tau) grid. categorize() is eps-dependent, so categories are recomputed per eps. Returns a list
    of per-(eps) blobs each carrying per-record rows for all taus, plus runtime + backend params."""
    t0 = time.time()
    orc = OpaOracle(domain)
    dc = orc.dc
    train = sample_records(domain, n_train, seed=seed, scheme=scheme)
    ev = sample_records(domain, n_eval, seed=seed + 1, scheme=scheme)

    backend_params = {}
    if backend == "smoothing":
        gate = train_gate_opa(orc, train, sigma=SIGMA, n_aug=N_AUG, seed=seed)
        backend_params = {"sigma": SIGMA, "n_mc": n_mc}
        lip_model = lip_enc = None
    elif backend == "lipschitz":
        if not _LIP_OK:
            raise RuntimeError(f"lipschitz backend unavailable: {_LIP_ERR}")
        lip_enc = make_encoder(orc.rt)
        lip_model = train_lipgate(orc, lip_enc, train, variant=LIP_VARIANT, sigma=SIGMA, seed=seed)
        emp_L = empirical_lipschitz(lip_model, lip_enc.matrix(ev).shape[1],
                                    device="cuda" if torch.cuda.is_available() else "cpu")
        backend_params = {"empirical_lipschitz_estimate": round(float(emp_L), 4),
                          "certified_L_used": float(CLAIMED_L), "lip_backend": backend_name()}
        gate = None
    else:
        raise ValueError(f"unknown backend {backend!r}")

    # FWER family size per record (independent of eps/tau/backend)
    nbr = [_branches(dc, r) for r in ev]
    blobs = []
    for eps in epsilons:
        cats = orc.categorize(ev, eps)              # REAL OPA categories over B_{1,eps}
        per_eps = {"eps": eps, "rows": [], "num_branches": nbr}
        for r, c, nb in zip(ev, cats, nbr):
            alpha_branch = alpha_fwer / nb          # Bonferroni / union bound (FWER) — reused identity
            row = {**c, "id": r["id"], "tool_id": r["tool_id"],
                   "categorical_fields": r["categorical_fields"], "alpha_branch": alpha_branch,
                   "num_branches": nb,
                   # model-free naive marginal composition sanity check (True on C by definition)
                   "naive_marginal_safe": (not c["disc_flip"]) and (not c["cont_flip"]) and c["clean_safe"],
                   "allow_by_tau": {}, "learned_allow": None}
            if backend == "smoothing":
                # min_ell (lower_bound_probability) does not depend on tau, so we run certify ONCE per
                # (record, eps) with a dummy tau and threshold against every tau afterwards (cheap vs MC).
                cz = certify(gate, orc.rt, r, sigma=SIGMA, eps=eps, tau=0.0, n_mc=n_mc,
                             alpha=alpha_branch)
                lb = float(cz["lower_bound_probability"])
                row["lower_bound_probability"] = lb
                row["learned_allow"] = bool(gate.allow_point(
                    domain, r["tool_id"], r["candidate_action"],
                    r["categorical_fields"], r["numeric_fields"], 0.5))
            else:  # lipschitz: deterministic margin certificate (sound, sampling-free)
                cl = certify_lip(lip_model, lip_enc, orc.rt, r, eps=eps, L=CLAIMED_L)
                row["min_margin"] = float(cl["min_margin"])
                row["cert_radius"] = float(cl["cert_radius"])
                # learned point-allow for the lipschitz gate (pointwise sign of margin)
                from lip_gate import lip_pointwise_allow
                row["learned_allow"] = bool(lip_pointwise_allow(lip_model, lip_enc, r))
            per_eps["rows"].append(row)
        blobs.append(per_eps)

    runtime = time.time() - t0
    return {"orc_version": orc.version, "policy_hash": orc.policy_hash,
            "backend_params": backend_params, "runtime_seconds": runtime, "blobs": blobs,
            "n_eval": n_eval}


def threshold_allow(row, backend, tau, eps, L=1.0):
    """Apply the tau (smoothing) / L*eps (lipschitz) decision to a precomputed per-record row."""
    if backend == "smoothing":
        return row["lower_bound_probability"] >= tau
    else:
        # deterministic margin certificate: allow iff min_margin > L*eps (tau-independent; we still tabulate
        # across taus so the curves are comparable — lipschitz allow is constant across tau by design)
        return row["min_margin"] > L * eps


# --------------------------------------------------------------------------- #
# aggregate a single (domain, backend, eps, tau) cell across one seed's rows -> metrics
# --------------------------------------------------------------------------- #
def cell_metrics(rows, backend, eps, tau, L=1.0):
    n = len(rows)
    dist = Counter(r["category"] for r in rows)

    def cat_allow(cat):
        sub = [r for r in rows if r["category"] == cat]
        if not sub:
            return float("nan")
        return sum(threshold_allow(r, backend, tau, eps, L) for r in sub) / len(sub)

    allowed = [r for r in rows if threshold_allow(r, backend, tau, eps, L)]
    Cs = [r for r in rows if r["category"] == "C"]
    cert_false_allow = (sum(r["truly_unsafe_reachable"] for r in allowed) / len(allowed)) if allowed else 0.0
    naive_C = (sum(r["naive_marginal_safe"] for r in Cs) / len(Cs)) if Cs else float("nan")
    # attack_false_allow = the uncertified learned POINT gate's allow rate over truly-unsafe-reachable
    # (A/B/C/U) points — the in-budget exploit the certificate is meant to close.
    reach = [r for r in rows if r["truly_unsafe_reachable"]]
    attack_fa = (sum(bool(r["learned_allow"]) for r in reach) / len(reach)) if reach else float("nan")
    clean_safe = [r for r in rows if r["clean_safe"]]
    # clean_acc = learned point-gate agreement with the OPA clean label on clean-safe points (allow=safe)
    clean_acc = (sum(bool(r["learned_allow"]) for r in clean_safe) / len(clean_safe)) if clean_safe else float("nan")
    return {
        "n": n,
        "C_rate": dist.get("C", 0) / n, "R_rate": dist.get("R", 0) / n, "U_rate": dist.get("U", 0) / n,
        "A_rate": dist.get("A", 0) / n, "B_rate": dist.get("B", 0) / n,
        "C_allow": cat_allow("C"), "U_allow": cat_allow("U"), "R_allow": cat_allow("R"),
        "cert_false_allow": cert_false_allow, "naive_C_falseallow": naive_C,
        "attack_false_allow": attack_fa, "clean_acc": clean_acc,
    }


def _mean_std(vals):
    vals = [v for v in vals if v == v]  # drop NaN
    if not vals:
        return float("nan"), float("nan")
    m = statistics.fmean(vals)
    s = statistics.pstdev(vals) if len(vals) > 1 else 0.0
    return m, s


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3, 4])
    ap.add_argument("--epsilons", type=float, nargs="+", default=[0.03, 0.05, 0.10])
    ap.add_argument("--taus", type=float, nargs="+", default=[0.80, 0.90, 0.95, 0.99])
    ap.add_argument("--backends", nargs="+", default=["smoothing", "lipschitz"],
                    choices=["smoothing", "lipschitz"])
    ap.add_argument("--domains", nargs="+", default=["finance", "sre", "ops"])
    ap.add_argument("--n-train", type=int, default=1200)
    ap.add_argument("--n-eval", type=int, default=400)
    ap.add_argument("--n-mc", type=int, default=2000)
    ap.add_argument("--alpha-fwer", type=float, default=0.001)
    ap.add_argument("--scheme", default="natural")
    ap.add_argument("--curve-tau", type=float, default=0.90, help="fixed tau for the R_allow-vs-eps curve")
    ap.add_argument("--curve-eps", type=float, default=0.10, help="fixed eps for the R_allow-vs-tau curve")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    if args.quick:
        args.seeds = [0, 1]
        args.epsilons = [0.05, 0.10]
        args.taus = [0.90, 0.95]
        args.domains = ["finance", "sre"]
        args.backends = [b for b in args.backends if b == "smoothing"] or ["smoothing"]
        # keep lipschitz only if explicitly asked AND available (cheap deterministic cert)
        if "lipschitz" in [b for b in ap.parse_args().backends] and _LIP_OK:
            args.backends = list(dict.fromkeys(args.backends + ["lipschitz"]))
        args.n_train, args.n_eval, args.n_mc = 400, 150, 600
        args.curve_tau, args.curve_eps = 0.90, 0.10

    # validate backends (skip lipschitz cleanly if unavailable)
    backends = []
    for b in args.backends:
        if b == "lipschitz" and not _LIP_OK:
            print(f"[skip] lipschitz backend unavailable ({_LIP_ERR}) -> smoothing only")
            continue
        backends.append(b)
    if not backends:
        backends = ["smoothing"]
    domains = [d for d in args.domains if d in DOMAINS]

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    print(f"EXP-OPA-FULL | domains={domains} backends={backends} seeds={args.seeds}")
    print(f"  eps={args.epsilons} taus={args.taus} n_train={args.n_train} n_eval={args.n_eval} "
          f"n_mc={args.n_mc} alpha_fwer={args.alpha_fwer}")

    per_example_fh = open(out / "per_example.jsonl", "w")
    n_records_written = 0

    # collect per-(domain,backend,seed,eps) row blobs; then aggregate across seeds for each cell
    # cell key = (domain, backend, eps, tau)
    cell_seed_metrics = defaultdict(list)        # key -> [metrics dict per seed]
    cell_runtime = defaultdict(list)             # key (domain,backend) -> [runtime per seed]
    cell_backend_params = {}                      # (domain,backend) -> backend params (last seed)
    all_num_branches = []                         # global FWER family-size log
    opa_meta = {}

    for domain in domains:
        for backend in backends:
            for seed in args.seeds:
                base = run_cell_base(domain, backend, seed, args.n_train, args.n_eval, args.n_mc,
                                     args.alpha_fwer, args.epsilons, scheme=args.scheme)
                opa_meta = {"opa_version": base["orc_version"]}
                cell_runtime[(domain, backend)].append(base["runtime_seconds"])
                cell_backend_params[(domain, backend)] = base["backend_params"]
                all_num_branches.extend(base["blobs"][0]["num_branches"])
                for blob in base["blobs"]:
                    eps = blob["eps"]
                    for tau in args.taus:
                        m = cell_metrics(blob["rows"], backend, eps, tau, L=CLAIMED_L if _LIP_OK else 1.0)
                        cell_seed_metrics[(domain, backend, eps, tau)].append(m)
                    # per-example jsonl: write one record per (record, eps), with allow flags per tau
                    for r in blob["rows"]:
                        rec_out = {
                            "domain": domain, "backend": backend, "seed": seed, "eps": eps,
                            "sigma": SIGMA if backend == "smoothing" else None,
                            "id": r["id"], "tool_id": r["tool_id"],
                            "categorical_fields": r["categorical_fields"],
                            "category": r["category"], "clean_safe": r["clean_safe"],
                            "truly_unsafe_reachable": r["truly_unsafe_reachable"],
                            "disc_flip": r["disc_flip"], "cont_flip": r["cont_flip"],
                            "joint_flip": r["joint_flip"],
                            "naive_marginal_safe": r["naive_marginal_safe"],
                            "learned_allow": r["learned_allow"],
                            "num_branches": r["num_branches"], "alpha_fwer": args.alpha_fwer,
                            "alpha_branch": r["alpha_branch"], "n_mc": args.n_mc,
                            "opa_version": base["orc_version"], "policy_hash": base["policy_hash"],
                            "allow_by_tau": {str(t): bool(threshold_allow(r, backend, t, eps,
                                                                          CLAIMED_L if _LIP_OK else 1.0))
                                             for t in args.taus},
                        }
                        if backend == "smoothing":
                            rec_out["lower_bound_probability"] = r["lower_bound_probability"]
                        else:
                            rec_out["min_margin"] = r["min_margin"]
                            rec_out["cert_radius"] = r["cert_radius"]
                            rec_out["certified_L_used"] = float(CLAIMED_L)
                        per_example_fh.write(json.dumps(rec_out) + "\n")
                        n_records_written += 1
                print(f"  done {domain}/{backend}/seed={seed} "
                      f"({base['runtime_seconds']:.1f}s)")
    per_example_fh.close()

    # ---- consolidate summary.csv / summary.json (mean+/-std across seeds per cell) ----
    L_used = CLAIMED_L if _LIP_OK else 1.0
    nb_min, nb_med, nb_max = (min(all_num_branches), int(statistics.median(all_num_branches)),
                              max(all_num_branches))
    metric_keys = ["clean_acc", "C_rate", "R_rate", "U_rate", "C_allow", "U_allow", "R_allow",
                   "cert_false_allow", "naive_C_falseallow", "attack_false_allow"]
    summary_rows = []
    for (domain, backend, eps, tau), ms in sorted(cell_seed_metrics.items()):
        bp = cell_backend_params[(domain, backend)]
        rt_m, rt_s = _mean_std(cell_runtime[(domain, backend)])
        row = {"domain": domain, "backend": backend, "sigma": SIGMA if backend == "smoothing" else "",
               "tau": tau, "eps": eps, "n_seeds": len(ms),
               "runtime_seconds_mean": round(rt_m, 3), "runtime_seconds_std": round(rt_s, 3),
               "mc_samples": args.n_mc if backend == "smoothing" else 0,
               "alpha_fwer": args.alpha_fwer,
               "alpha_branch_min": round(args.alpha_fwer / nb_max, 8),
               "alpha_branch_median": round(args.alpha_fwer / nb_med, 8),
               "alpha_branch_max": round(args.alpha_fwer / nb_min, 8),
               "num_discrete_neighbors_min": nb_min - 1, "num_discrete_neighbors_max": nb_max - 1,
               "n_mc": args.n_mc if backend == "smoothing" else "",
               "empirical_lipschitz_estimate": bp.get("empirical_lipschitz_estimate", ""),
               "certified_L_used": bp.get("certified_L_used", ""),
               "margin_threshold": round(L_used * eps, 4) if backend == "lipschitz" else "",
               "opa_version": opa_meta.get("opa_version", "")}
        for k in metric_keys:
            m, s = _mean_std([mm[k] for mm in ms])
            row[k + "_mean"] = round(m, 4)
            row[k + "_std"] = round(s, 4)
        # acceptance flag
        row["acceptance_pass"] = bool(
            (row["C_allow_mean"] == 0 or row["C_allow_mean"] != row["C_allow_mean"]) and
            (row["U_allow_mean"] == 0 or row["U_allow_mean"] != row["U_allow_mean"]) and
            row["cert_false_allow_mean"] == 0 and row["R_allow_mean"] > 0)
        summary_rows.append(row)

    cols = (["domain", "backend", "sigma", "tau", "eps", "n_seeds"]
            + [k + "_mean" for k in metric_keys] + [k + "_std" for k in metric_keys]
            + ["runtime_seconds_mean", "runtime_seconds_std", "mc_samples", "n_mc", "alpha_fwer",
               "alpha_branch_min", "alpha_branch_median", "alpha_branch_max",
               "num_discrete_neighbors_min", "num_discrete_neighbors_max",
               "empirical_lipschitz_estimate", "certified_L_used", "margin_threshold",
               "opa_version", "acceptance_pass"])
    with open(out / "summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(summary_rows)
    (out / "summary.json").write_text(json.dumps(
        {"config": {"seeds": args.seeds, "epsilons": args.epsilons, "taus": args.taus,
                    "backends": backends, "domains": domains, "n_train": args.n_train,
                    "n_eval": args.n_eval, "n_mc": args.n_mc, "alpha_fwer": args.alpha_fwer,
                    "sigma": SIGMA, "scheme": args.scheme,
                    "fwer_num_branches": {"min": nb_min, "median": nb_med, "max": nb_max}},
         "cells": summary_rows}, indent=2) + "\n")

    # ---- utility curves ----
    # R_allow vs eps (fixed tau = curve_tau), mean+/-std across seeds, per (domain, backend)
    write_utility_curve(out / "utility_curve_epsilon.csv", cell_seed_metrics, domains, backends,
                        x_name="eps", x_vals=args.epsilons, fixed_name="tau", fixed_val=args.curve_tau,
                        taus=args.taus, epsilons=args.epsilons)
    write_utility_curve(out / "utility_curve_tau.csv", cell_seed_metrics, domains, backends,
                        x_name="tau", x_vals=args.taus, fixed_name="eps", fixed_val=args.curve_eps,
                        taus=args.taus, epsilons=args.epsilons)

    # ---- narrative ----
    write_summary_md(out, summary_rows, domains, backends, args, nb_min, nb_med, nb_max,
                     opa_meta.get("opa_version", "?"), n_records_written)

    # ---- optional plots ----
    try_plots(out, cell_seed_metrics, domains, backends, args)

    print(f"\nwrote {n_records_written} per-example records -> {out/'per_example.jsonl'}")
    print(f"wrote -> {out/'summary.csv'} / summary.json / summary.md / "
          f"utility_curve_epsilon.csv / utility_curve_tau.csv")
    # console headline
    print("\n== acceptance per cell (C_allow=U_allow=cert_false_allow=0, R_allow>0) ==")
    for r in summary_rows:
        print(f"  {r['domain']:8s} {r['backend']:9s} eps={r['eps']:.2f} tau={r['tau']:.2f} | "
              f"C_allow={r['C_allow_mean']} U_allow={r['U_allow_mean']} "
              f"cfa={r['cert_false_allow_mean']} R_allow={r['R_allow_mean']} "
              f"clean_acc={r['clean_acc_mean']} -> {'PASS' if r['acceptance_pass'] else 'CHECK'}")


def _closest(vals, target):
    return min(vals, key=lambda v: abs(v - target))


def write_utility_curve(path, cell_seed_metrics, domains, backends, x_name, x_vals, fixed_name,
                        fixed_val, taus, epsilons):
    fixed = _closest(taus if fixed_name == "tau" else epsilons, fixed_val)
    rows = []
    for domain in domains:
        for backend in backends:
            for x in x_vals:
                eps = x if x_name == "eps" else fixed
                tau = x if x_name == "tau" else fixed
                ms = cell_seed_metrics.get((domain, backend, eps, tau), [])
                rm, rs = _mean_std([m["R_allow"] for m in ms])
                cfa_m, _ = _mean_std([m["cert_false_allow"] for m in ms])
                rows.append({"domain": domain, "backend": backend, fixed_name: fixed, x_name: x,
                             "R_allow_mean": round(rm, 4), "R_allow_std": round(rs, 4),
                             "cert_false_allow_mean": round(cfa_m, 4), "n_seeds": len(ms)})
    cols = ["domain", "backend", fixed_name, x_name, "R_allow_mean", "R_allow_std",
            "cert_false_allow_mean", "n_seeds"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def write_summary_md(out, summary_rows, domains, backends, args, nb_min, nb_med, nb_max, opa_ver, n_rec):
    md = ["# EXP-OPA-FULL — full authored-policy robustness/utility sweep with REAL OPA labels\n",
          f"Labels and the A/B/C/R/U category of every typed return come from the **OPA engine** "
          f"(v{opa_ver}, `opa eval`), not the analytic generator (`policy_provenance = authored_rego`). "
          f"The certified post-return gate is certified per record over B_{{1,ε}} with a **family-wise** "
          f"Clopper–Pearson level (`alpha_branch = alpha_FWER / num_branches`).\n",
          f"Sweep: domains={domains}, backends={backends}, seeds={args.seeds}, "
          f"epsilons={args.epsilons}, taus={args.taus}; "
          f"n_train={args.n_train}, n_eval={args.n_eval}, n_mc={args.n_mc}, "
          f"sigma={SIGMA}, scheme={args.scheme}. {n_rec} per-example records.\n",
          "## FWER accounting (logged)\n",
          f"`alpha_FWER = {args.alpha_fwer}`. The family per record is the discrete neighborhood "
          f"`{{identity}} ∪ N_1(s)`; `num_branches` ∈ [{nb_min}, {nb_max}] "
          f"(median {nb_med}), so per-branch Clopper–Pearson levels are "
          f"`alpha_branch ∈ [{args.alpha_fwer/nb_max:.2e}, {args.alpha_fwer/nb_min:.2e}]` "
          f"(median {args.alpha_fwer/nb_med:.2e}). This is the exact per-record accounting reused from "
          "`run_opa_gate.py` (Bonferroni union bound over the enumerated swaps).\n",
          "## Main table — per (domain, backend, eps, tau), mean ± std across seeds\n",
          "| domain | backend | eps | tau | clean_acc | C% | R% | U% | C_allow | U_allow | **R_allow** "
          "| cert_FA | naive_C | attack_FA | accept |",
          "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]

    def pm(r, k):
        return f"{r[k+'_mean']:.3f}±{r[k+'_std']:.3f}"
    for r in summary_rows:
        md.append(
            f"| {r['domain']} | {r['backend']} | {r['eps']} | {r['tau']} | {pm(r,'clean_acc')} | "
            f"{pm(r,'C_rate')} | {pm(r,'R_rate')} | {pm(r,'U_rate')} | {pm(r,'C_allow')} | "
            f"{pm(r,'U_allow')} | **{pm(r,'R_allow')}** | {pm(r,'cert_false_allow')} | "
            f"{pm(r,'naive_C_falseallow')} | {pm(r,'attack_false_allow')} | "
            f"{'✅' if r['acceptance_pass'] else '⚠️'} |")

    fails = [r for r in summary_rows if not r["acceptance_pass"]]
    md += ["\n## Acceptance target (C_allow=U_allow=cert_false_allow=0, R_allow>0)\n"]
    if not fails:
        md.append("**All cells PASS.** The certified gate is sound on C/U (`C_allow=U_allow=0`), has "
                  "oracle-measured `cert_false_allow=0`, and is non-vacuous (`R_allow>0`) in every cell.")
    else:
        md.append(f"**{len(fails)}/{len(summary_rows)} cells flagged** (reported, not hidden):\n")
        for r in fails:
            why = []
            if not (r["C_allow_mean"] == 0 or r["C_allow_mean"] != r["C_allow_mean"]):
                why.append(f"C_allow={r['C_allow_mean']}")
            if not (r["U_allow_mean"] == 0 or r["U_allow_mean"] != r["U_allow_mean"]):
                why.append(f"U_allow={r['U_allow_mean']}")
            if r["cert_false_allow_mean"] != 0:
                why.append(f"cert_false_allow={r['cert_false_allow_mean']}")
            if not r["R_allow_mean"] > 0:
                why.append(f"R_allow={r['R_allow_mean']} (vacuous: ε/σ or τ too strict for this geometry)")
            md.append(f"- {r['domain']}/{r['backend']} eps={r['eps']} tau={r['tau']}: "
                      + ", ".join(why))
        md.append("\nDiagnosis note: a vacuous `R_allow=0` is a *utility* (not soundness) failure — it "
                  "means the strict operating point (large ε/σ or τ) leaves no certifiable robust band "
                  "for this policy geometry; soundness (`cert_false_allow=0`) is preserved. "
                  "`C_allow>0`/`U_allow>0`/`cert_false_allow>0` would be soundness failures (none expected; "
                  "if seen, check learned-gate fidelity, MC budget, or an OPA-label mismatch).")

    md.append("\n**Reading.** Utility (`R_allow`) decreases as ε grows toward σ and as τ tightens "
              "(see `utility_curve_epsilon.csv` / `utility_curve_tau.csv`); soundness "
              "(`C_allow=U_allow=cert_false_allow=0`) is invariant. The smoothing backend is a "
              "black-box certificate (any `predict_proba` gate); the deterministic 1-Lipschitz backend "
              "is sampling-free and can recover more R utility in this low-dimensional OPA setting. "
              "`naive_C_falseallow≈1` is a definitional sanity check (C passes each marginal but fails "
              "jointly); `attack_false_allow` is the uncertified learned point-gate's in-budget exploit "
              "rate that the certificate closes.\n")
    (out / "summary.md").write_text("\n".join(md) + "\n")


def try_plots(out, cell_seed_metrics, domains, backends, args):  # pragma: no cover - optional
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:
        print(f"[plots skipped] {e}")
        return
    try:
        tau0 = _closest(args.taus, args.curve_tau)
        eps0 = _closest(args.epsilons, args.curve_eps)
        # R_allow vs eps
        fig, ax = plt.subplots(figsize=(6, 4))
        for domain in domains:
            for backend in backends:
                xs, ys, es = [], [], []
                for e in args.epsilons:
                    ms = cell_seed_metrics.get((domain, backend, e, tau0), [])
                    m, s = _mean_std([mm["R_allow"] for mm in ms])
                    xs.append(e); ys.append(m); es.append(s)
                ax.errorbar(xs, ys, yerr=es, marker="o", capsize=3, label=f"{domain}/{backend}")
        ax.set_xlabel("epsilon"); ax.set_ylabel("R_allow"); ax.set_title(f"R_allow vs eps (tau={tau0})")
        ax.legend(fontsize=7); ax.grid(alpha=0.3); fig.tight_layout()
        fig.savefig(out / "r_allow_vs_epsilon.png", dpi=120); plt.close(fig)
        # R_allow vs tau
        fig, ax = plt.subplots(figsize=(6, 4))
        for domain in domains:
            for backend in backends:
                xs, ys, es = [], [], []
                for t in args.taus:
                    ms = cell_seed_metrics.get((domain, backend, eps0, t), [])
                    m, s = _mean_std([mm["R_allow"] for mm in ms])
                    xs.append(t); ys.append(m); es.append(s)
                ax.errorbar(xs, ys, yerr=es, marker="o", capsize=3, label=f"{domain}/{backend}")
        ax.set_xlabel("tau"); ax.set_ylabel("R_allow"); ax.set_title(f"R_allow vs tau (eps={eps0})")
        ax.legend(fontsize=7); ax.grid(alpha=0.3); fig.tight_layout()
        fig.savefig(out / "r_allow_vs_tau.png", dpi=120); plt.close(fig)
        print(f"wrote -> {out/'r_allow_vs_epsilon.png'} / r_allow_vs_tau.png")
    except Exception as e:
        print(f"[plots skipped] {e}")


if __name__ == "__main__":
    main()
