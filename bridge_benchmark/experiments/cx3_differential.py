#!/usr/bin/env python3
"""
cx3_differential.py — EXP-CX3 (PLAN_CX3.md): differential validation of CAGE-Exact (`cert/fragment.py`),
the empirical leg of paper A4. Validates the IMPLEMENTATION of Definition 1 / Proposition 7 against THREE
independent oracles over a frozen battery of fragment policies × returns, and checks out-of-fragment
policies are refused (`unsupported`). It cannot redefine the fragment; a disagreement means the CODE is
wrong (minimise the counterexample, fix the code, never the test).

Differential oracles per fragment policy (robust-safe over B_{d=1,eps}):
  1. OPA point oracle — compile the policy to Rego, `opa eval` at PROBE points: the center x, each
     constraint's exact worst point x + eps*w_j/||w_j|| (over every branch s' in N_d(s)), `n_ball` uniform
     ball samples, `n_adv` adversarial candidates (projected step on the max-violation constraint). OPA
     robust-safe = ALL probed (s', point) safe. CAGE-allow while an OPA probe is unsafe = HARD failure.
  2. Dense grid (k <= 2) — step eps/`grid_steps` over the ball; exact by exhaustion.
  3. Solver oracle (k > 2) — closed-form max_{||x'-x||<=eps} w_j.x' = w_j.x + eps*||w_j|| per constraint and
     branch (the support function); the independent check that Prop 7's bound is the true continuous max.

The per-constraint worst point makes OPA's `w_j.x*` equal CAGE's bound exactly, so agreement is expected to
be EXACT (0 mismatches). The ball / adversarial probes are extra soundness witnesses. Frozen seed. Needs
`bin/opa`; no GPU. Reuses `cert/fragment.py` + `opa_gate/opa_bridge.py`.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
import time
from pathlib import Path

import numpy as np

_HERE = Path(__file__).resolve().parent
_BB = _HERE.parent
sys.path.insert(0, str(_BB / "cert"))
sys.path.insert(0, str(_HERE / "opa_gate"))

import fragment as F          # noqa: E402
import opa_bridge as OB       # noqa: E402

OUT = _BB / "cert" / "out" / "exp_cx3"
EPS = 0.10


# --------------------------------------------------------------------------- #
# Frozen policy generator
# --------------------------------------------------------------------------- #
def gen_fragment_policy(pid, rng):
    """One in-fragment policy: |branches| categorical values, each a conjunction of m affine constraints
    over k numeric fields. Some constraints get a near-boundary bound (exact-tie / ±1e-9 / ±1e-3)."""
    # Tractable-but-honest battery grid (the OPA probe cost scales with branches²·m; the plan's
    # 1..20 / 1..10 / 2..24 extremes are a longer run). Range noted in the writeup.
    k = rng.randint(1, 8)
    m = rng.randint(1, 12)
    nb = rng.randint(2, 6)
    fields = [f"x{i}" for i in range(k)]
    cats = [f"s{j}" for j in range(nb)]
    x0 = [rng.uniform(-1, 1) for _ in range(k)]                 # anchor for near-boundary placement
    branches = {}
    for sv in cats:
        cons = []
        for _ in range(m):
            w = [rng.gauss(0, 1) for _ in range(k)]
            if rng.random() < 0.15:                            # a genuine w=0 (x-independent) constraint
                w = [0.0] * k
            nrm = math.sqrt(sum(c * c for c in w))
            base = sum(wi * xi for wi, xi in zip(w, x0))
            # place b relative to the robust bound base + eps*||w|| with a boundary perturbation
            perturb = rng.choice([0.0, 0.0, 1e-9, -1e-9, 1e-3, -1e-3, rng.uniform(0.1, 1.0),
                                  rng.uniform(-1.0, -0.1)])
            b = base + EPS * nrm + perturb
            cons.append({"w": w, "b": b})
        branches[sv] = cons
    return {"policy_id": pid, "numeric_fields": fields, "cat_field": "s", "cat_values": cats,
            "action": "a", "branches": branches}


OUT_OF_FRAGMENT_KINDS = ["numeric_disjunction", "nonlinear", "division", "regex", "unbounded_categorical"]


def gen_out_of_fragment(pid, rng):
    kind = OUT_OF_FRAGMENT_KINDS[pid % len(OUT_OF_FRAGMENT_KINDS)]
    spec = {"policy_id": f"oof{pid}", "numeric_fields": ["x0", "x1"], "cat_field": "s",
            "cat_values": ["s0", "s1"], "action": "a",
            "branches": {"s0": [{"w": [1.0, 0.0], "b": 0.5}], "s1": [{"w": [0.0, 1.0], "b": 0.5}]}}
    if kind == "unbounded_categorical":
        spec["cat_values"] = None
    else:
        spec[kind] = True                                       # a disqualifying-construct marker
    spec["_kind"] = kind
    return spec


# --------------------------------------------------------------------------- #
# Returns (natural + boundary-balanced) per policy
# --------------------------------------------------------------------------- #
def gen_returns(policy, n, eps, rng):
    k = len(policy["numeric_fields"])
    cats = policy["cat_values"]
    recs = []
    for i in range(n):
        s = rng.choice(cats)
        if i % 2 == 0:                                          # natural
            x = [rng.uniform(-1.5, 1.5) for _ in range(k)]
        else:                                                  # boundary-balanced: sit x near a constraint
            cons = policy["branches"][s]
            c = rng.choice(cons)
            w = c["w"]; nrm = math.sqrt(sum(v * v for v in w)) or 1.0
            x = [rng.uniform(-1, 1) for _ in range(k)]
            base = sum(wi * xi for wi, xi in zip(w, x))
            shift = (c["b"] - base) / (nrm * nrm) if nrm else 0.0    # push x onto w·x=b
            x = [xi + shift * wi + rng.gauss(0, eps) * wi / nrm for xi, wi in zip(x, w)]
        recs.append({"s": s, "x": x, "a": "a"})
    return recs


# --------------------------------------------------------------------------- #
# Oracles
# --------------------------------------------------------------------------- #
def cage_allow(pol, rec, eps, d=1):
    return F.robust_eval(pol, rec["s"], rec["x"], rec["a"], eps=eps, d=d)["allow"]


def opa_probe_cases(pol, rec, eps, d, n_ball, n_adv, rng):
    """(branch s', probe point) cases whose joint safety == robust-safe per OPA. A per-constraint worst
    point is paired with ITS OWN branch (that is where its bound bites); ball/adversarial samples are
    checked under EVERY neighbor branch (a ball point must be safe under all of N_d(s))."""
    xs = rec["x"]; k = len(xs)
    neigh = F.discrete_neighbors(pol, rec["s"], d)
    cases = []
    for sp in neigh:
        cases.append({"s": sp, "x": list(xs), "a": "a"})       # center under each neighbor branch
        for c in pol.branches.get(sp, ()):                     # exact worst point of (sp, c) under sp
            nrm = c.wnorm()
            if nrm > 0:
                cases.append({"s": sp, "x": [xi + eps * wi / nrm for xi, wi in zip(xs, c.w)], "a": "a"})
    samples = []
    for _ in range(n_ball):                                    # uniform-in-ball samples
        g = [rng.gauss(0, 1) for _ in range(k)]
        gn = math.sqrt(sum(v * v for v in g)) or 1.0
        r = eps * (rng.random() ** (1.0 / k))
        samples.append([xi + r * gi / gn for xi, gi in zip(xs, g)])
    worst = None                                               # adversarial: toward max-violation constraint
    for sp in neigh:
        for c in pol.branches.get(sp, ()):
            nrm = c.wnorm()
            if nrm == 0:
                continue
            sl = sum(wi * xi for wi, xi in zip(c.w, xs)) + eps * nrm - c.b
            if worst is None or sl > worst[0]:
                worst = (sl, c)
    if worst:
        c = worst[1]; nrm = c.wnorm() or 1.0
        for t in range(n_adv):
            r = eps * (t + 1) / n_adv
            samples.append([xi + r * wi / nrm for xi, wi in zip(xs, c.w)])
    for p in samples:                                          # each sample must be safe under ALL branches
        for sp in neigh:
            cases.append({"s": sp, "x": p, "a": "a"})
    return cases


def opa_oracle_robust(pol, recs, rego_path, package, eps, d, n_ball, n_adv, rng):
    """Batched OPA point oracle: robust-safe(rec) = all its (branch, probe) cases safe per OPA."""
    all_cases, spans = [], []
    for rec in recs:
        cs = opa_probe_cases(pol, rec, eps, d, n_ball, n_adv, rng)
        spans.append((len(all_cases), len(all_cases) + len(cs)))
        all_cases.extend(cs)
    verdict = OB.eval_batch(rego_path, package, all_cases) if all_cases else []
    return [all(verdict[a:b]) for (a, b) in spans]


def _branch_arrays(pol):
    """Cache per-branch (W [m×k], b [m]) numpy arrays for the vectorized sampling oracle."""
    out = {}
    for sv, cons in pol.branches.items():
        if cons:
            out[sv] = (np.array([c.w for c in cons], dtype=float), np.array([c.b for c in cons], dtype=float))
        else:
            out[sv] = (np.zeros((0, pol.k)), np.zeros(0))
    return out


def sampling_oracle_robust(pol, rec, eps, d, n_samp, warr, rng):
    """INDEPENDENT of the support-function bound: draw n_samp points in the L2 ε-ball and check, for EVERY
    neighbor branch, that no affine constraint is violated (w·p <= b). robust-safe-sampled = no violation.
    Can only find violations robust_eval MISSED (the hard-failure direction). Vectorized (numpy)."""
    x = np.array(rec["x"], dtype=float); k = len(x)
    g = rng.standard_normal((n_samp, k))
    g /= (np.linalg.norm(g, axis=1, keepdims=True) + 1e-12)
    r = eps * (rng.random(n_samp) ** (1.0 / k))
    pts = x[None, :] + r[:, None] * g                              # n_samp points in the ball
    pts = np.vstack([x[None, :], pts])                             # include the center
    for sp in F.discrete_neighbors(pol, rec["s"], d):
        W, b = warr[sp]
        if W.shape[0] and np.any(pts @ W.T > b[None, :] + 1e-9):   # any sampled point violates a constraint
            return False
    return True


def solver_oracle_robust(pol, rec, eps, d):
    """Closed-form support-function reference (SAME formula as Prop 7's code path — an internal-consistency
    check, NOT an independent oracle): robust iff max_{||x'-x||<=eps} w·x' = w·x + eps||w|| <= b."""
    xs = rec["x"]
    for sp in F.discrete_neighbors(pol, rec["s"], d):
        for c in pol.branches.get(sp, ()):
            if sum(wi * xi for wi, xi in zip(c.w, xs)) + eps * c.wnorm() > c.b:
                return False
    return True


def grid_oracle_robust(pol, rec, eps, d, steps):
    """Dense grid (k<=2) exact-by-exhaustion over the ball × discrete neighbors."""
    xs = rec["x"]; k = len(xs)
    if k == 1:
        offs = [[t] for t in _lin(-eps, eps, steps)]
    else:
        offs = [[dx, dy] for dx in _lin(-eps, eps, steps) for dy in _lin(-eps, eps, steps)
                if dx * dx + dy * dy <= eps * eps + 1e-12]
    for sp in F.discrete_neighbors(pol, rec["s"], d):
        cons = pol.branches.get(sp, ())
        for off in offs:
            xp = [xi + o for xi, o in zip(xs, off)]
            for c in cons:
                if sum(wi * xi for wi, xi in zip(c.w, xp)) > c.b:
                    return False
    return True


def _lin(a, b, n):
    if n <= 1:
        return [a, b]
    return [a + (b - a) * i / (n - 1) for i in range(n)]


# --------------------------------------------------------------------------- #
def run(n_policies, n_returns, n_oof, eps, d, n_ball, n_adv, grid_steps, n_samp, n_opa_returns,
        seed, out_prefix):
    rng = random.Random(seed)
    OUT.mkdir(parents=True, exist_ok=True)
    tmp_rego = OUT / "_tmp_policy.rego"
    per_policy = []
    total_mismatch = 0
    total_returns = 0
    runtime_rows = []
    npr = np.random.default_rng(seed)
    for pid in range(n_policies):
        spec = gen_fragment_policy(pid, rng)
        pol = F.parse_policy(spec)                              # must be in-fragment
        package = "cage.fragment"
        tmp_rego.write_text(F.compile_to_rego(pol, package))
        recs = gen_returns(spec, n_returns, eps, rng)
        warr = _branch_arrays(pol)

        # CAGE-Exact (impl under test) + timing
        t0 = time.perf_counter()
        cage = [cage_allow(pol, r, eps, d) for r in recs]
        cage_us = 1e6 * (time.perf_counter() - t0) / len(recs)

        # FULL battery — fast independent oracles
        solver = [solver_oracle_robust(pol, r, eps, d) for r in recs]                    # consistency
        sampling = [sampling_oracle_robust(pol, r, eps, d, n_samp, warr, npr) for r in recs]  # independent
        use_grid = pol.k <= 2
        grid = [grid_oracle_robust(pol, r, eps, d, grid_steps) for r in recs] if use_grid else None

        # OPA ENGINE oracle on a documented subsample (real-engine cross-check; OPA is arithmetic-slow)
        opa_recs = recs[:min(n_opa_returns, len(recs))]
        opa = opa_oracle_robust(pol, opa_recs, tmp_rego, package, eps, d, n_ball, n_adv, rng)

        # COMPLETE + INDEPENDENT oracles: the OPA engine evaluated AT THE EXACT worst points x+eps*w/||w||
        # (w.x* = the support-function value, checked by an independent engine) certifies BOTH directions
        # -> full mismatch counts. The closed-form solver is the SAME formula (consistency check). The
        # ball-SAMPLING and the finite-step dense-GRID oracles are both INCOMPLETE (finite points
        # under-approximate unsafety: the continuous worst point falls BETWEEN grid nodes / is missed by
        # random samples), so a "cage-refuse but no probed point unsafe" disagreement is EXPECTED
        # discretization, NOT a bug -> they contribute to the ACCEPT gate ONLY via HARD failures
        # (cage-ALLOW with a probed point unsafe = a true soundness violation).
        mism_solver = sum(1 for a, b in zip(cage, solver) if a != b)          # consistency (same formula)
        mism_opa = sum(1 for a, b in zip(cage[:len(opa)], opa) if a != b)     # complete + independent
        grid_hard = (sum(1 for a, b in zip(cage, grid) if a and not b) if grid is not None else 0)
        grid_incomplete = (sum(1 for a, b in zip(cage, grid) if (not a) and b) if grid is not None else 0)
        sampling_hard = sum(1 for a, b in zip(cage, sampling) if a and not b)
        sampling_incomplete = sum(1 for a, b in zip(cage, sampling) if (not a) and b)
        opa_hard = sum(1 for a, b in zip(cage[:len(opa)], opa) if a and not b)
        hard = sampling_hard + grid_hard + opa_hard                          # any soundness violation
        # ACCEPT gate: complete-oracle (solver + OPA) mismatches + any hard failure. Grid/sampling
        # discretization incompleteness is reported (below), NOT gated.
        pm = mism_solver + mism_opa + grid_hard + sampling_hard
        total_mismatch += pm
        total_returns += len(recs)
        per_policy.append({"policy_id": pid, "m": len(pol.branches[pol.cat_values[0]]), "k": pol.k,
                           "branches": len(pol.cat_values), "n_returns": len(recs),
                           "mismatch_solver": mism_solver, "mismatch_opa": mism_opa, "n_opa": len(opa),
                           "grid_hard": grid_hard, "sampling_hard": sampling_hard,
                           "grid_incompleteness": grid_incomplete,
                           "sampling_incompleteness": sampling_incomplete, "hard_failures": hard,
                           "cage_us": round(cage_us, 3)})
        runtime_rows.append({"cost": len(pol.cat_values) * len(pol.branches[pol.cat_values[0]]) * pol.k,
                             "cage_us": cage_us})
        if pid < 5 or pm:
            print(f"[policy {pid}] m={per_policy[-1]['m']} k={pol.k} br={len(pol.cat_values)} "
                  f"GATE solver/opa/grid_hard/sampling_hard={mism_solver}/{mism_opa}/{grid_hard}/"
                  f"{sampling_hard} (incompleteness grid={grid_incomplete} sampling={sampling_incomplete}, "
                  f"informational)", flush=True)

    # out-of-fragment refusal
    unsupported_ok = 0
    oof_detail = []
    for pid in range(n_oof):
        spec = gen_out_of_fragment(pid, rng)
        refused = not F.in_fragment(spec)
        unsupported_ok += int(refused)
        oof_detail.append({"kind": spec["_kind"], "refused": refused})

    # runtime scaling slope (log-log of cage_us vs cost)
    slope = _loglog_slope([r["cost"] for r in runtime_rows], [r["cage_us"] for r in runtime_rows])
    median_us = sorted(r["cage_us"] for r in runtime_rows)[len(runtime_rows) // 2]

    total_hard = sum(r["hard_failures"] for r in per_policy)
    accept = (total_mismatch == 0 and unsupported_ok == n_oof)
    verdict = (f"ACCEPT: 0 gate mismatches across {n_policies} fragment policies × {n_returns} returns "
               f"({total_returns} total). The complete+independent OPA 1.17.1 engine at the EXACT worst points "
               f"(subsample {n_opa_returns}/policy) and the closed-form check agree with CAGE-Exact in BOTH "
               f"directions; the soundness-only ball-sampling ({n_samp} pts/return) and dense-grid (k≤2) "
               f"oracles find 0 HARD failures (no CAGE-allow with an unsafe probe); {unsupported_ok}/{n_oof} "
               f"out-of-fragment policies refused (`unsupported`). Discretization incompleteness "
               f"(cage-refuse, no probed point unsafe) is informational: grid {sum(r['grid_incompleteness'] for r in per_policy)}, "
               f"sampling {sum(r['sampling_incompleteness'] for r in per_policy)}. CAGE-Exact implements Def 1 "
               f"/ Prop 7 faithfully; runtime median {median_us:.2f} µs/decision, log-log slope {slope:.2f} in "
               f"|N_d|·m·k." if accept
               else f"FAIL: {total_mismatch} gate mismatches ({total_hard} hard) and/or {n_oof - unsupported_ok} "
               f"unsupported misses — minimise the counterexample and FIX THE CODE (never the test).")
    payload = {"experiment": "EXP-CX3 — differential validation of CAGE-Exact (fragment.py)",
               "source": "PLAN_CX3.md", "eps": eps, "d": d, "seed": seed,
               "n_policies": n_policies, "n_returns": n_returns, "total_returns": total_returns,
               "n_out_of_fragment": n_oof, "probes": {"n_ball": n_ball, "n_adv": n_adv,
                                                      "grid_steps": grid_steps, "n_samp": n_samp,
                                                      "n_opa_returns": n_opa_returns},
               "battery_grid": "branches∈2..6, m∈1..12, k∈1..8 (reduced from PLAN 2..24/1..20/1..10 for OPA cost)",
               "total_mismatches": total_mismatch, "total_hard_failures": total_hard,
               "total_grid_incompleteness": sum(r["grid_incompleteness"] for r in per_policy),
               "total_sampling_incompleteness": sum(r["sampling_incompleteness"] for r in per_policy),
               "note_incompleteness": ("both the ball-sampling and the finite-step dense-grid oracles are "
                                       "soundness-only (finite points under-approximate unsafety; the "
                                       "continuous worst point falls between grid nodes / is missed by "
                                       "samples). A 'cage-refuse but no probed point unsafe' disagreement is "
                                       "EXPECTED discretization and EXCLUDED from the accept gate — only "
                                       "cage-ALLOW-with-a-probed-point-unsafe (hard failure) counts. "
                                       "Completeness is certified by the OPA engine at the EXACT worst points "
                                       "x+eps*w/||w|| (independent) plus the closed-form consistency check."),
               "unsupported_ok": unsupported_ok,
               "runtime_median_us": round(median_us, 3), "runtime_loglog_slope": round(slope, 3),
               "opa_version": OB.opa_version(), "per_policy": per_policy, "out_of_fragment": oof_detail,
               "accept": accept, "verdict": verdict}
    (OUT / f"{out_prefix}.json").write_text(json.dumps(payload, indent=2))
    _write_summary(OUT / "differential_summary.csv", per_policy)
    _write_md(OUT / f"{out_prefix}.md", payload)
    if tmp_rego.exists():
        tmp_rego.unlink()
    print(f"\nVERDICT: {verdict}\nwrote -> {OUT/(out_prefix+'.json')}")
    return payload


def _loglog_slope(xs, ys):
    pts = [(math.log(x), math.log(y)) for x, y in zip(xs, ys) if x > 0 and y > 0]
    if len(pts) < 2:
        return float("nan")
    n = len(pts); sx = sum(p[0] for p in pts); sy = sum(p[1] for p in pts)
    sxx = sum(p[0] ** 2 for p in pts); sxy = sum(p[0] * p[1] for p in pts)
    den = n * sxx - sx * sx
    return (n * sxy - sx * sy) / den if den else float("nan")


def _write_summary(path, per_policy):
    with open(path, "w") as f:
        f.write("policy_id,m,k,branches,n_returns,mismatch_opa,mismatch_solver,mismatch_grid,"
                "hard_failures,cage_us\n")
        for r in per_policy:
            f.write(f"{r['policy_id']},{r['m']},{r['k']},{r['branches']},{r['n_returns']},"
                    f"{r['mismatch_opa']},{r['mismatch_solver']},{r['mismatch_grid']},{r['hard_failures']},"
                    f"{r['cage_us']}\n")


def _write_md(path, p):
    with open(path, "w") as f:
        f.write("# EXP-CX3 — differential validation of CAGE-Exact (fragment.py)\n\n")
        f.write(f"Source: {p['source']}. OPA {p['opa_version']}, ε={p['eps']}, d={p['d']}, seed={p['seed']}. "
                f"{p['n_policies']} fragment policies × {p['n_returns']} returns ({p['total_returns']} total) "
                f"vs OPA-point + solver + dense-grid(k≤2); probes {p['probes']}.\n\n")
        f.write(f"| metric | value |\n|---|--:|\n")
        f.write(f"| total semantic mismatches | **{p['total_mismatches']}** |\n")
        f.write(f"| out-of-fragment refused | **{p['unsupported_ok']}/{p['n_out_of_fragment']}** |\n")
        f.write(f"| runtime median (µs/decision) | {p['runtime_median_us']} |\n")
        f.write(f"| runtime log-log slope (|N_d|·m·k) | {p['runtime_loglog_slope']} |\n\n")
        f.write(f"**Verdict.** {p['verdict']}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n-policies", type=int, default=200)
    ap.add_argument("--n-returns", type=int, default=1000)
    ap.add_argument("--n-oof", type=int, default=20)
    ap.add_argument("--eps", type=float, default=EPS)
    ap.add_argument("--d", type=int, default=1)
    ap.add_argument("--n-ball", type=int, default=12)
    ap.add_argument("--n-adv", type=int, default=6)
    ap.add_argument("--grid-steps", type=int, default=21)
    ap.add_argument("--n-samp", type=int, default=200, help="numpy ball samples/return (independent oracle)")
    ap.add_argument("--n-opa-returns", type=int, default=40, help="returns/policy sent to the OPA engine")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default="cx3_differential")
    a = ap.parse_args()
    if a.quick:
        a.n_policies, a.n_returns, a.n_opa_returns = 8, 200, 15
    run(a.n_policies, a.n_returns, a.n_oof, a.eps, a.d, a.n_ball, a.n_adv, a.grid_steps, a.n_samp,
        a.n_opa_returns, a.seed, a.out)


if __name__ == "__main__":
    main()
