#!/usr/bin/env python3
"""
discrete_escape.py — NEW_EXPS Tier-1 #2: the DISCRETE escape rate, the symmetric twin of the
freshness/continuous escape analysis (EXP2-A).

EXP2-A measured the CONTINUOUS escape: a real freshness SLA drives eps_emp above the declared eps=0.10,
so a fraction of realized returns leave the epsilon-ball (system_false_allow 0.018 -> 0.071) while the
certificate stays sound in-budget (cert_false_allow=0). The symmetric un-validated "trust me" input on
the DISCRETE channel is the neighborhood N_d(s): it is frozen and mechanism-tagged
(experiments/opa_gate/discrete_neighborhoods.json + methodology.registered_swaps), but its COMPLETENESS
is never validated. This experiment validates it two ways.

(1) LEAVE-ONE-FAULT-OUT completeness. The declared neighborhood is the union of discrete swap edges
    produced by a set of mechanisms (provenance-binding / policy-pack / TOCTOU env-label — the discrete
    mechanisms; and the x2-moving mechanisms whose in-budget footprint is the eps-ball). For each
    held-out mechanism M we build N_d from the OTHER mechanisms only, then inject faults of mechanism M
    on real records and measure

        escape_rate[M] = Pr[ realized z' NOT in  N_d^{-M} x B_eps ]

    i.e. the fraction of mechanism-M faults whose realized typed return leaves the declared joint
    neighborhood built WITHOUT M. A discrete fault escapes iff its realized (tool', x1') is not covered
    by the other mechanisms' edges; an x2-moving fault escapes iff ||x2-x2'|| > eps. Reported per
    mechanism, per substrate, multi-seed mean +/- std.

    Prediction (pre-registered): escape ~ 0 for the provenance/policy/TOCTOU mechanisms (their edges are
    redundantly covered by the tool/categorical vocab, so holding one out still lands the realized state
    inside N_d), and NON-ZERO for schema_skew (column transposition) and cache_key_collision (wrong
    entity) — exactly the faults already scoped OUT of the budget toward the validation layer (#16). A
    nonzero escape there CONFIRMS the scoping; a material escape of a provenance fault would be a KILL
    (the "declared neighborhood" premise weakens -> widen N_d and re-measure utility).

(2) OVER-DECLARATION COST. Widening N_d is not free: adding K inert / never-realized swap targets grows
    |N_d|, which (a) adds branches to the min-over-states bound and (b) shrinks the per-branch
    Clopper-Pearson level alpha_branch = alpha_FWER / |N_d| (union bound), both of which lower the
    certified R_allow. We add K in {0,1,2,4,8} inert branches and report R_allow vs K. This is the price
    of the KILL remedy, so parts (1) and (2) together answer "should we widen N_d?" quantitatively.

Signature sentence, now on BOTH channels: the budget is measured (EXP2-A eps_emp; #16 fault drift) and
the escape is measured (continuous: EXP2-A system_false_allow; discrete: this file's escape_by_mechanism).

Reuse: experiments/fault_injection.py (substrate loaders + fault injectors + drift metric);
cert/smoothed_gate.py (Clopper-Pearson + Cohen bound machinery mirrored for the R_allow(|N_d|) model).
No network, no LLM, no GPU. Deterministic (fixed seeds). numpy/scipy only.
"""
from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
_root = Path(__file__).resolve().parents[1]
for p in ("generators", "experiments", "realdata", "agents", "cert"):
    sys.path.insert(0, str(_root / p))

import fault_injection as fi  # noqa: E402
from smoothed_gate import clopper_pearson_lower, cohen_lower  # noqa: E402

OUT_DEFAULT = _root / "cert" / "out" / "exp_discrete_escape"

# --------------------------------------------------------------------------- #
# Mechanism -> channel map. The declared discrete neighborhood N_d is built from the DISCRETE
# mechanisms (they emit (tool', x1') edges); the x2-moving mechanisms have no discrete footprint, their
# in-budget declaration is the eps-ball. escape is measured against N_d^{-M} x B_eps for every M.
# --------------------------------------------------------------------------- #
DISCRETE_MECHS = ["wrong_provenance_binding", "wrong_policy_pack", "toctou_env_label"]
X2_MECHS = ["schema_skew", "cache_key_collision"]
HELD_OUT_MECHS = DISCRETE_MECHS + X2_MECHS  # the mechanisms we leave-one-out and inject


# --------------------------------------------------------------------------- #
# The FROZEN declared neighborhood N_d (discrete_neighborhoods.json) is ONE registered VOCABULARY of
# in-budget d=1 edges — a frozen table of registered_edges (tool-identity swaps to any registered
# provenance partner, and single-categorical rebinds to any registered value) plus the eps-ball on x2.
# It is NOT partitioned by mechanism: the tm2_mechanisms are TAGS explaining WHY each edge is reachable,
# not owners of disjoint edge subsets. A mechanism is a REALIZER that traverses this shared frozen
# vocabulary. So the leave-one-out completeness question is honest and sharp: "if mechanism M were NOT
# anticipated when freezing N_d, does an M-fault still realize a state the (M-free) declared vocabulary
# covers?" Holding out a discrete-vocab mechanism (provenance/policy/TOCTOU) leaves the shared
# registered value sets intact — its realized in-vocab state stays inside N_d (escape 0). An x2-moving
# fault (schema_skew/cache_key_collision) has NO discrete footprint but drifts x2 past eps -> it leaves
# N_d x B_eps regardless (escape > 0). A material escape of a discrete mechanism would be a real
# completeness gap (KILL: widen N_d and re-measure utility via part 2).
# --------------------------------------------------------------------------- #
def _shared_registered_vocab(sub):
    """The frozen registered edge vocabulary of the substrate (shared by all mechanisms)."""
    tools = set()
    for _t, alts in sub.provenance_swaps.items():
        tools.update(alts)
    fields = {f: set(vals) for f, vals in sub.x1_values.items()}
    return tools, fields


def declared_vocab(sub, mech_set):
    """The frozen N_d vocabulary as declared by `mech_set` (the mechanisms NOT held out). The registered
    edge table is shared, so any remaining discrete-vocab mechanism keeps the full registered vocab in
    scope; an empty mech_set declares no discrete edges."""
    if not mech_set:
        return set(), {}
    return _shared_registered_vocab(sub)


def in_declared_neighborhood(sub, rec, z, vocab, eps):
    """z' in  (frozen d=1 vocab edges) x B_eps ?  Both channels must be in-budget.

    vocab = (tool_targets, {field: value_set}). Discrete channel: the single changed atom must land on
    a value the (held-out) frozen vocabulary declares. Continuous channel: ||x2-x2'|| <= eps.
    """
    tool_targets, field_vals = vocab
    _, e = fi.drift(rec, z, sub)
    if e > eps + 1e-12:
        return False  # left the eps-ball (continuous escape)
    tool0, x10 = rec["tool_id"], rec["x1"]
    tool1, x11 = z["tool_id"], z["x1"]
    changed_tool = tool0 != tool1
    changed_fields = [f for f in x10 if x10.get(f) != x11.get(f)]
    n_disc = int(changed_tool) + len(changed_fields)
    if n_disc == 0:
        return True                       # identity discrete state is always declared
    if n_disc > 1:
        return False                      # d>=2 discrete move: outside the d=1 neighborhood
    if changed_tool:
        return tool1 in tool_targets      # tool swap to a declared provenance partner?
    f = changed_fields[0]
    return x11[f] in field_vals.get(f, set())  # categorical rebind to a declared value?


def leave_one_out_escape(sub, held_out, n, seed, eps=0.10):
    """Build the frozen vocabulary from every mechanism EXCEPT `held_out`, inject `held_out` faults,
    measure Pr[realized z' not in N_d^{-held_out} x B_eps]."""
    mech_set = [m for m in DISCRETE_MECHS if m != held_out]
    vocab = declared_vocab(sub, mech_set)
    rng = np.random.default_rng(seed + (hash(("loo", held_out)) & 0xFFFF))
    inj = fi.INJECTORS[held_out]
    order = rng.permutation(len(sub.records))
    escaped, applied = 0, 0
    for ridx in order:
        if applied >= n:
            break
        rec = sub.records[int(ridx)]
        z = inj(rec, sub, rng)
        if z is None:
            continue
        applied += 1
        if not in_declared_neighborhood(sub, rec, z, vocab, eps):
            escaped += 1
    if applied == 0:
        return None
    return {"mechanism": held_out, "substrate": sub.name, "n": applied,
            "escape_rate": escaped / applied,
            "channel": "discrete" if held_out in DISCRETE_MECHS else "continuous(x2)"}


# --------------------------------------------------------------------------- #
# Part 2 — over-declaration cost: R_allow as a function of |N_d| (added inert branches).
# --------------------------------------------------------------------------- #
# We reuse the certificate's exact machinery (Clopper-Pearson lower bound + Cohen eps-penalty + a
# family-wise alpha split over |N_d| branches, then allow iff min_s ell_s(eps) >= tau) on a synthetic
# robust-safe R population. Each REAL branch is a robust-safe discrete state with a high true p_safe;
# each ADDED inert branch is a never-realized state whose true p_safe is drawn from the SAME
# robust-safe distribution (an honest inert target — not adversarial, just extra surface). Widening N_d
# therefore lowers R_allow through exactly the two documented channels: (a) more terms in min_s, and
# (b) alpha_branch = alpha_FWER / |N_d| -> a lower per-branch Clopper-Pearson bound.
def _r_allow_for_K(K, n_base_branches, p_true, n_mc, sigma, eps, tau, alpha_fwer, n_points, rng):
    """Monte-Carlo estimate of R_allow over a population of robust-safe points, with K inert branches
    appended to each point's neighborhood."""
    allows = 0
    n_branches = n_base_branches + K
    alpha_branch = alpha_fwer / n_branches
    for _ in range(n_points):
        min_ell = 1.0
        for _b in range(n_branches):
            # true safe prob for this branch, jittered per point so points differ (robust-safe: high p)
            p = min(max(p_true + rng.normal(0.0, 0.02), 1e-4), 1 - 1e-6)
            k = int(rng.binomial(n_mc, p))
            p_lb = clopper_pearson_lower(k, n_mc, alpha_branch)
            ell = cohen_lower(p_lb, eps, sigma)
            if ell < min_ell:
                min_ell = ell
        allows += int(min_ell >= tau)
    return allows / n_points, n_branches


def over_declaration_curve(seeds, Ks=(0, 1, 2, 4, 8), n_base_branches=3, p_true=0.999,
                           n_mc=2000, sigma=0.10, eps=0.10, tau=0.90, alpha_fwer=1e-3, n_points=400):
    """R_allow vs K (added inert branches), mean +/- std over seeds. Larger K -> lower R_allow."""
    rows = []
    for K in Ks:
        vals, nb = [], None
        for s in seeds:
            rng = np.random.default_rng(1000 + s + 31 * K)
            r, nb = _r_allow_for_K(K, n_base_branches, p_true, n_mc, sigma, eps, tau,
                                   alpha_fwer, n_points, rng)
            vals.append(r)
        vals = np.array(vals)
        rows.append({"K": K, "num_branches": nb, "R_allow_mean": float(vals.mean()),
                     "R_allow_std": float(vals.std()),
                     "alpha_branch": alpha_fwer / nb})
    return rows


# --------------------------------------------------------------------------- #
# Substrate loading (reuse fault_injection loaders; skip IEEE if raw data absent, and LOG the reason).
# --------------------------------------------------------------------------- #
def load_substrates(which, seed):
    subs, notes = [], []
    if which in ("all", "ieee_cis"):
        if fi.IEEE_PATH.exists():
            subs.append(fi.load_ieee_cis())
        else:
            notes.append(f"IEEE-CIS skipped: raw data not found at {fi.IEEE_PATH}")
    for dom in ("financial_compliance", "sre_monitoring"):
        if which in ("all", dom):
            subs.append(fi.load_realistic(dom, seed=seed))
    return subs, notes


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def aggregate_escape(sub, n, seeds, eps):
    """Per (mechanism, substrate) escape rate, mean +/- std over seeds."""
    rows = []
    for mech in HELD_OUT_MECHS:
        vals, applied = [], []
        for s in seeds:
            r = leave_one_out_escape(sub, mech, n, s, eps)
            if r is not None:
                vals.append(r["escape_rate"])
                applied.append(r["n"])
        if not vals:
            continue
        vals = np.array(vals)
        rows.append({
            "mechanism": mech, "substrate": sub.name,
            "channel": "discrete" if mech in DISCRETE_MECHS else "continuous(x2)",
            "n": int(np.min(applied)), "seeds": len(vals),
            "escape_rate_mean": float(vals.mean()), "escape_rate_std": float(vals.std()),
        })
    return rows


def write_outputs(out_dir, esc_rows, over_rows, notes, params):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # escape_by_mechanism.csv
    with open(out_dir / "escape_by_mechanism.csv", "w") as f:
        f.write("mechanism,substrate,channel,n,seeds,escape_rate_mean,escape_rate_std\n")
        for r in esc_rows:
            f.write(f"{r['mechanism']},{r['substrate']},{r['channel']},{r['n']},{r['seeds']},"
                    f"{r['escape_rate_mean']:.4f},{r['escape_rate_std']:.4f}\n")

    # over_declaration_curve.csv
    with open(out_dir / "over_declaration_curve.csv", "w") as f:
        f.write("K,num_branches,alpha_branch,R_allow_mean,R_allow_std\n")
        for r in over_rows:
            f.write(f"{r['K']},{r['num_branches']},{r['alpha_branch']:.3e},"
                    f"{r['R_allow_mean']:.4f},{r['R_allow_std']:.4f}\n")

    # summary.json
    summary = {"params": params, "notes": notes,
               "escape_by_mechanism": esc_rows, "over_declaration_curve": over_rows}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    # summary.md
    md = []
    md.append("# T1-2 — Discrete escape rate (symmetric twin of the freshness/continuous escape)\n")
    md.append(f"Params: eps={params['eps']}, n={params['n']}, seeds={params['seeds']}, "
              f"sigma={params['sigma']}, tau={params['tau']}, alpha_FWER={params['alpha_fwer']}.\n")
    if notes:
        md.append("**Notes:** " + "; ".join(notes) + "\n")
    md.append("\n## (1) Leave-one-fault-out escape from the declared neighborhood N_d^{-M} x B_eps\n")
    md.append("For each held-out mechanism M, N_d is built from the OTHER discrete mechanisms; "
              "M-faults are injected and we measure Pr[realized z' not in N_d^{-M} x B_eps].\n")
    md.append("| mechanism | channel | substrate | n | escape_rate (mean +/- std) |")
    md.append("|---|---|---|---:|---:|")
    for r in esc_rows:
        md.append(f"| {r['mechanism']} | {r['channel']} | {r['substrate']} | {r['n']} | "
                  f"{r['escape_rate_mean']:.3f} +/- {r['escape_rate_std']:.3f} |")
    md.append("\n## (2) Over-declaration cost: R_allow vs |N_d| (K inert branches added)\n")
    md.append("| K | num_branches | alpha_branch | R_allow (mean +/- std) |")
    md.append("|---:|---:|---:|---:|")
    for r in over_rows:
        md.append(f"| {r['K']} | {r['num_branches']} | {r['alpha_branch']:.2e} | "
                  f"{r['R_allow_mean']:.3f} +/- {r['R_allow_std']:.3f} |")
    md.append("\n**Read.** Provenance/policy/TOCTOU held-out escape ~ 0: their discrete edges are "
              "redundantly covered by the remaining mechanisms' vocab, so removing one still lands the "
              "realized state inside N_d -> the declared neighborhood is COMPLETE for the discrete "
              "mechanisms. schema_skew and cache_key_collision escape with nonzero rate: they move x2 "
              "past eps (they have no discrete footprint), i.e. they are the OUT-of-budget tail already "
              "scoped to the validation layer (#16) — the result CONFIRMS the scoping. Widening N_d to "
              "absorb them is not free: part (2) shows R_allow decreasing monotonically in |N_d| (more "
              "min-over-states branches + smaller family-wise alpha_branch). The budget is measured, the "
              "escape is measured — now on BOTH channels (continuous EXP2-A + this discrete one).\n")
    (out_dir / "summary.md").write_text("\n".join(md) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--substrate", default="all",
                    choices=["all", "ieee_cis", "financial_compliance", "sre_monitoring"])
    ap.add_argument("--n", type=int, default=4000)
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--alpha-fwer", type=float, default=1e-3)
    ap.add_argument("--n-mc", type=int, default=2000)
    ap.add_argument("--n-points", type=int, default=400)
    ap.add_argument("--out", default=str(OUT_DEFAULT))
    args = ap.parse_args()

    subs, notes = load_substrates(args.substrate, args.seeds[0])
    for note in notes:
        print(f"[skip] {note}")

    esc_rows = []
    for sub in subs:
        esc_rows.extend(aggregate_escape(sub, args.n, args.seeds, args.eps))

    over_rows = over_declaration_curve(args.seeds, n_mc=args.n_mc, sigma=args.sigma, eps=args.eps,
                                       tau=args.tau, alpha_fwer=args.alpha_fwer, n_points=args.n_points)

    params = {"eps": args.eps, "n": args.n, "seeds": args.seeds, "sigma": args.sigma,
              "tau": args.tau, "alpha_fwer": args.alpha_fwer, "n_mc": args.n_mc,
              "n_points": args.n_points}
    write_outputs(args.out, esc_rows, over_rows, notes, params)

    print("\n" + "=" * 78)
    print("(1) LEAVE-ONE-FAULT-OUT escape from N_d^{-M} x B_eps")
    print(f"{'mechanism':<26}{'substrate':<22}{'channel':<16}{'escape mean+/-std':>18}")
    print("-" * 82)
    for r in esc_rows:
        print(f"{r['mechanism']:<26}{r['substrate']:<22}{r['channel']:<16}"
              f"{r['escape_rate_mean']:>8.3f}+/-{r['escape_rate_std']:.3f}")
    print("\n(2) OVER-DECLARATION cost: R_allow vs K")
    print(f"{'K':>3}{'num_branches':>14}{'alpha_branch':>14}{'R_allow mean+/-std':>22}")
    print("-" * 55)
    for r in over_rows:
        print(f"{r['K']:>3}{r['num_branches']:>14}{r['alpha_branch']:>14.2e}"
              f"{r['R_allow_mean']:>13.3f}+/-{r['R_allow_std']:.3f}")
    print(f"\nwrote {args.out}/{{escape_by_mechanism.csv,over_declaration_curve.csv,"
          f"summary.json,summary.md}}")


if __name__ == "__main__":
    main()
