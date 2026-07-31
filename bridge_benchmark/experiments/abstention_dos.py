#!/usr/bin/env python3
"""
abstention_dos.py — Tier-2 #9: ABSTENTION-DoS, attacking the PRICE of soundness.

New angle (not in the literature we know of). Prop-4 gives the certified gate SOUNDNESS: it never
approves an action that a bounded joint adversary B_{1,eps} could flip to unsafe (cert_false_allow=0).
The price of that guarantee is ABSTENTION: whenever the gate cannot certify allow over the whole
eps-ball it defers to the downstream human circuit ("R" = certified-safe region auto-executes, the
rest abstains). An adversary who cannot force a false-allow can still attack AVAILABILITY: by
*selecting* boundary-seeking inputs (records whose analytic oracle margin m is near 0, so no
robust-safe certificate exists) it can INFLATE the abstention rate far above the benign baseline ->
an alert-fatigue / human-circuit DoS. The false-allow surface is traded for an availability surface.

We quantify:
  1. ATTACK: abstain_benign (natural traffic, dominated by clearly-safe records deep in R) vs
     abstain_adv (adversary selects from the boundary band |m| <= delta_band, top fraction ranked by
     proximity to the certified-safe boundary). INFLATION FACTOR = abstain_adv / abstain_benign,
     across seeds and selection strengths.
  2. SOUNDNESS INVARIANT: cert_false_allow stays 0.000 under BOTH selections (the attack costs
     availability, never safety) -- that is the whole framing.
  3. MITIGATIONS + their cost:
       (i) per-source abstention rate-limit / budget: bound the DoS amplification a single source can
           inflict (caps the inflation factor at a chosen ceiling; cost = dropped/queued adversarial
           volume, no safety cost).
       (ii) adaptive eps: shrink the certified radius under abstention pressure to reclaim some of the
           boundary band into the certifiable region (trades robustness radius for availability) ->
           an abstention-inflation-vs-safety-radius trade-off curve.

REUSE. Record pool = the real IEEE-CIS balanced set
(`data/realdata/ieee_cis_boundary_balanced_s0.jsonl`); the analytic authorization oracle
(`realdata/ieee_cis_policy.py`, theta_base/delta/eps from the generation config). The CERTIFIED GATE
here is the EXACT analytic certificate (allow iff the record is in the analytic R region = clean-safe
AND robust over every d=1 provenance swap AND the eps continuous move; abstain otherwise). This is the
sound, deterministic, model-free gate -- it makes cert_false_allow=0 hold BY CONSTRUCTION so the
experiment isolates the AVAILABILITY axis, not gate fidelity (the learned-gate story is #32).

Deterministic (seeded selection RNG). Pure numpy + stdlib; no torch/MC/LLM/network.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

_root = Path(__file__).resolve().parents[1]
for p in ("generators", "realdata"):
    sys.path.insert(0, str(_root / p))

import ieee_cis_policy as pol  # noqa: E402

OUT_DEFAULT = _root / "cert" / "out" / "exp_abstention_dos"
IEEE_PATH = _root / "data" / "realdata" / "ieee_cis_boundary_balanced_s0.jsonl"

# policy constants (from the generation config shipped with the pool)
THETA_BASE = 0.488808
DELTA = 0.08
EPS = 0.10


# --------------------------------------------------------------------------- #
# Pool + oracle margin
# --------------------------------------------------------------------------- #
def load_pool(path=IEEE_PATH, n=None):
    recs = []
    with open(path) as f:
        for line in f:
            o = json.loads(line)
            recs.append({"tool_id": o["tool_id"], "x1": dict(o["x1"]),
                         "risk_score": float(o["x2"]["risk_score"]),
                         "fraud": int(o["meta"]["isFraud"])})
    if n:
        recs = recs[:n]
    return recs


def oracle_margin(rec, theta_base=THETA_BASE, delta=DELTA):
    """Signed analytic margin on the record's OWN state: m = risk - theta_self. unsafe iff m>=0.
    |m| small == boundary-seeking (least room for a robust-safe certificate)."""
    th = pol.threshold_for_tool(theta_base, rec["tool_id"], rec["x1"], delta)
    return rec["risk_score"] - th


def certified_allow(rec, eps, theta_base=THETA_BASE, delta=DELTA):
    """EXACT analytic certificate == analytic Category R: clean-safe AND no d=1 swap and no <=eps risk
    move (jointly) flips to unsafe. allow iff category == 'R'. Abstain (defer to human) otherwise.
    Sound by construction: an R record cannot be flipped in B_{1,eps} -> cert_false_allow == 0."""
    cat = pol.analytic_category(rec["risk_score"], rec["tool_id"], rec["x1"],
                                theta_base, delta, eps)["category"]
    return cat == "R"


def reachable_unsafe(rec, eps, theta_base=THETA_BASE, delta=DELTA):
    """True iff SOME z' in B_{1,eps}(rec) is unsafe (any d=1 swap + <=eps risk move flips). If the gate
    allows such a record that is a FALSE-ALLOW. category in {A,B,C,U} <=> reachable-unsafe."""
    cat = pol.analytic_category(rec["risk_score"], rec["tool_id"], rec["x1"],
                                theta_base, delta, eps)["category"]
    return cat != "R"


# --------------------------------------------------------------------------- #
# Selection distributions (the ADVERSARY vs BENIGN input model)
# --------------------------------------------------------------------------- #
def _sample_weighted(rng, weights, n):
    w = np.asarray(weights, dtype=np.float64)
    w = np.clip(w, 1e-12, None)
    w = w / w.sum()
    return rng.choice(len(w), size=n, replace=True, p=w)


# benign traffic is dominated by clearly-legitimate transactions sitting DEEP inside the safe region
# (margin well below -eps, comfortably certifiable). We model that with a benign weight peaked at a
# deep-safe target margin m* and decaying with distance. NOTE the pool is boundary-BALANCED by
# construction (2000 records/category, only 20% ever certifiable), so the benign abstention floor here
# is CONSERVATIVE: a real production stream (mostly clearly-safe) would abstain far less, making the
# inflation factor LARGER than we report. We report the conservative lower bound.
_BENIGN_MSTAR = -0.30
_BENIGN_SCALE = 0.10


def benign_selection(pool, margins, rng, n):
    """Natural traffic: clearly-safe deep-interior records dominate; boundary cases are rare."""
    m = np.asarray(margins)
    w = np.exp(-np.abs(m - _BENIGN_MSTAR) / _BENIGN_SCALE)
    idx = _sample_weighted(rng, w, n)
    return [pool[i] for i in idx]


def adversarial_selection(pool, margins, rng, n, strength):
    """Adversary SELECTS boundary-seeking inputs to maximize abstention. `strength` in (0,1] = the
    fraction of the draw the adversary can steer (the rest is benign cover traffic it cannot control).
    Steered draws are ranked by proximity to the certified-safe boundary (|m| small) and sampled from
    the boundary band with weight w = exp(-|m|/band). strength=1 == fully boundary-seeking."""
    band = 0.05
    m = np.asarray(margins)
    w_band = np.exp(-np.abs(m) / band)
    n_adv = int(round(strength * n))
    n_ben = n - n_adv
    idx_adv = _sample_weighted(rng, w_band, n_adv) if n_adv > 0 else np.array([], dtype=int)
    ben = benign_selection(pool, margins, rng, n_ben) if n_ben > 0 else []
    return [pool[i] for i in idx_adv] + ben


# --------------------------------------------------------------------------- #
# Metrics on a selected batch
# --------------------------------------------------------------------------- #
def batch_metrics(batch, eps, theta_base=THETA_BASE, delta=DELTA):
    allow = np.array([certified_allow(r, eps, theta_base, delta) for r in batch])
    abstain = ~allow
    unsafe = np.array([reachable_unsafe(r, eps, theta_base, delta) for r in batch])
    # false-allow = gate allowed a record that IS reachable-unsafe in B_{1,eps}
    false_allow = float(np.mean(allow & unsafe)) if len(batch) else 0.0
    return {"abstain_rate": float(np.mean(abstain)) if len(batch) else 0.0,
            "allow_rate": float(np.mean(allow)) if len(batch) else 0.0,
            "cert_false_allow": false_allow,
            "n": len(batch)}


# --------------------------------------------------------------------------- #
# MITIGATION 1: per-source abstention rate-limit / budget
# --------------------------------------------------------------------------- #
def mitigate_rate_limit(batch, eps, budget_frac, theta_base=THETA_BASE, delta=DELTA):
    """A single source is granted an abstention BUDGET = budget_frac * n requests. Once its abstention
    budget is exhausted the source is throttled: further would-be-abstain requests from it are DROPPED
    (rate-limited / queued for batched human review), not fanned out one-by-one to the on-call human.
    This BOUNDS the amplification a single adversarial source can inflict on the human circuit. Cost =
    dropped adversarial request volume; NO safety cost (dropped requests are never auto-allowed)."""
    budget = int(round(budget_frac * len(batch)))
    used = 0
    served_abstain = 0
    dropped = 0
    allow = 0
    unsafe_allowed = 0
    for r in batch:
        if certified_allow(r, eps, theta_base, delta):
            allow += 1
            if reachable_unsafe(r, eps, theta_base, delta):
                unsafe_allowed += 1
        else:
            if used < budget:
                used += 1
                served_abstain += 1
            else:
                dropped += 1
    n = len(batch)
    # abstentions actually delivered to the human circuit (the DoS load) after throttling
    human_load = served_abstain / n if n else 0.0
    return {"human_abstain_load": human_load,
            "dropped_frac": dropped / n if n else 0.0,
            "allow_rate": allow / n if n else 0.0,
            "cert_false_allow": (unsafe_allowed / n) if n else 0.0}


# --------------------------------------------------------------------------- #
# MITIGATION 2: adaptive eps (shrink the certified radius under abstention pressure)
# --------------------------------------------------------------------------- #
def mitigate_adaptive_eps(batch, eps_full, eps_min, theta_base=THETA_BASE, delta=DELTA):
    """Under abstention pressure, shrink the certified radius eps -> eps' (>= eps_min). A smaller ball
    reclaims boundary records into R (higher availability) but certifies robustness only up to eps',
    NOT eps_full. This is the abstention-vs-safety-radius trade: we report abstention at eps' AND the
    HONEST residual exposure = records now allowed that were reachable-unsafe within the FULL declared
    radius eps_full (the robustness the operator gave up). At eps'=eps_full there is no exposure."""
    allow_eps = np.array([certified_allow(r, eps_full, theta_base, delta) for r in batch])
    allow_shrunk = np.array([certified_allow(r, eps_min, theta_base, delta) for r in batch])
    # residual exposure: newly-allowed by shrinking that are unsafe within the FULL radius
    newly = allow_shrunk & ~allow_eps
    unsafe_full = np.array([reachable_unsafe(r, eps_full, theta_base, delta) for r in batch])
    residual_exposure = float(np.mean(newly & unsafe_full)) if len(batch) else 0.0
    # w.r.t. the ADVERTISED (shrunk) radius the gate is still sound:
    unsafe_shrunk = np.array([reachable_unsafe(r, eps_min, theta_base, delta) for r in batch])
    fa_shrunk = float(np.mean(allow_shrunk & unsafe_shrunk)) if len(batch) else 0.0
    return {"eps": eps_min,
            "abstain_rate": float(np.mean(~allow_shrunk)) if len(batch) else 0.0,
            "allow_rate": float(np.mean(allow_shrunk)) if len(batch) else 0.0,
            "cert_false_allow_advertised": fa_shrunk,      # sound w.r.t. eps' -> 0
            "residual_exposure_vs_full_eps": residual_exposure}


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def run(seeds, n, eps, strengths, out_dir, quick=False):
    pool = load_pool()
    margins_full = np.array([oracle_margin(r) for r in pool])

    # ---- 1. ATTACK: inflation across seeds x selection strengths ----
    inflation_rows = []
    for strength in strengths:
        ab_ben, ab_adv, cfa_ben, cfa_adv, infl = [], [], [], [], []
        for s in seeds:
            rng = np.random.default_rng(1000 + s)
            ben_batch = benign_selection(pool, margins_full, rng, n)
            adv_batch = adversarial_selection(pool, margins_full, rng, n, strength)
            mb = batch_metrics(ben_batch, eps)
            ma = batch_metrics(adv_batch, eps)
            ab_ben.append(mb["abstain_rate"]); ab_adv.append(ma["abstain_rate"])
            cfa_ben.append(mb["cert_false_allow"]); cfa_adv.append(ma["cert_false_allow"])
            infl.append(ma["abstain_rate"] / mb["abstain_rate"] if mb["abstain_rate"] > 0 else float("nan"))
        inflation_rows.append({
            "selection_strength": strength,
            "abstain_benign_mean": float(np.mean(ab_ben)), "abstain_benign_std": float(np.std(ab_ben)),
            "abstain_adv_mean": float(np.mean(ab_adv)), "abstain_adv_std": float(np.std(ab_adv)),
            "inflation_factor_mean": float(np.nanmean(infl)), "inflation_factor_std": float(np.nanstd(infl)),
            "cert_false_allow_benign": float(np.mean(cfa_ben)),
            "cert_false_allow_adv": float(np.mean(cfa_adv)),
        })

    # ---- 2 + 3. MITIGATIONS: measured at the strongest attack (strength=1.0) ----
    strong = max(strengths)
    # a fixed strong-attack batch per seed
    mit_rows = []
    # baseline (no mitigation) inflation at the strong attack, for the reduction number
    base_adv, base_ben = [], []
    strong_batches = []
    for s in seeds:
        rng = np.random.default_rng(2000 + s)
        ben = benign_selection(pool, margins_full, rng, n)
        adv = adversarial_selection(pool, margins_full, rng, n, strong)
        strong_batches.append((ben, adv))
        base_ben.append(batch_metrics(ben, eps)["abstain_rate"])
        base_adv.append(batch_metrics(adv, eps)["abstain_rate"])
    base_ben_m = float(np.mean(base_ben)); base_adv_m = float(np.mean(base_adv))
    base_infl = base_adv_m / base_ben_m if base_ben_m > 0 else float("nan")

    # Mitigation 1: rate-limit at a few source budgets
    budgets = [0.30] if quick else [0.50, 0.30, 0.15]
    for bf in budgets:
        loads, drops, cfas = [], [], []
        for (_, adv) in strong_batches:
            r = mitigate_rate_limit(adv, eps, bf)
            loads.append(r["human_abstain_load"]); drops.append(r["dropped_frac"]); cfas.append(r["cert_false_allow"])
        load_m = float(np.mean(loads))
        infl_after = load_m / base_ben_m if base_ben_m > 0 else float("nan")
        mit_rows.append({
            "mitigation": "rate_limit", "param": f"budget_frac={bf}",
            "abstain_adv_after": load_m, "inflation_after": infl_after,
            "cost": f"dropped_frac={float(np.mean(drops)):.3f}",
            "cert_false_allow": float(np.mean(cfas)),
        })

    # Mitigation 2: adaptive eps sweep (shrink radius -> reclaim availability)
    eps_grid = [EPS, 0.06] if quick else [EPS, 0.08, 0.06, 0.04, 0.02]
    for ep in eps_grid:
        abst, expo, fas = [], [], []
        for (_, adv) in strong_batches:
            r = mitigate_adaptive_eps(adv, EPS, ep)
            abst.append(r["abstain_rate"]); expo.append(r["residual_exposure_vs_full_eps"])
            fas.append(r["cert_false_allow_advertised"])
        ab_m = float(np.mean(abst))
        infl_after = ab_m / base_ben_m if base_ben_m > 0 else float("nan")
        mit_rows.append({
            "mitigation": "adaptive_eps", "param": f"eps={ep}",
            "abstain_adv_after": ab_m, "inflation_after": infl_after,
            "cost": f"residual_exposure_vs_full_eps={float(np.mean(expo)):.4f}",
            "cert_false_allow": float(np.mean(fas)),
        })

    summary = {
        "experiment": "T2-9 abstention-DoS (attacking the price of soundness)",
        "n_per_batch": n, "seeds": list(seeds), "eps_full": eps,
        "policy": {"theta_base": THETA_BASE, "delta": DELTA, "eps": EPS},
        "attack": inflation_rows,
        "baseline_strong_attack": {"strength": strong, "abstain_benign": base_ben_m,
                                    "abstain_adv": base_adv_m, "inflation_factor": base_infl},
        "mitigations": mit_rows,
        "soundness_invariant": {
            "cert_false_allow_max_over_all_conditions": max(
                [row["cert_false_allow_benign"] for row in inflation_rows]
                + [row["cert_false_allow_adv"] for row in inflation_rows]
                + [row["cert_false_allow"] for row in mit_rows]),
            "note": "0.0 => soundness invariant under the DoS attack and under both mitigations.",
        },
    }
    _write_outputs(out_dir, inflation_rows, mit_rows, summary)
    return summary


def _write_outputs(out_dir, inflation_rows, mit_rows, summary):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(out_dir / "inflation.csv", "w") as f:
        f.write("selection_strength,abstain_benign_mean,abstain_benign_std,abstain_adv_mean,"
                "abstain_adv_std,inflation_factor_mean,inflation_factor_std,cert_false_allow_benign,"
                "cert_false_allow_adv\n")
        for r in inflation_rows:
            f.write(f"{r['selection_strength']},{r['abstain_benign_mean']:.4f},"
                    f"{r['abstain_benign_std']:.4f},{r['abstain_adv_mean']:.4f},"
                    f"{r['abstain_adv_std']:.4f},{r['inflation_factor_mean']:.4f},"
                    f"{r['inflation_factor_std']:.4f},{r['cert_false_allow_benign']:.4f},"
                    f"{r['cert_false_allow_adv']:.4f}\n")

    with open(out_dir / "mitigation.csv", "w") as f:
        f.write("mitigation,param,abstain_adv_after,inflation_after,cost,cert_false_allow\n")
        for r in mit_rows:
            f.write(f"{r['mitigation']},{r['param']},{r['abstain_adv_after']:.4f},"
                    f"{r['inflation_after']:.4f},{r['cost']},{r['cert_false_allow']:.4f}\n")

    with open(out_dir / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    _write_md(out_dir / "summary.md", summary, inflation_rows, mit_rows)
    _maybe_figure(out_dir, inflation_rows, mit_rows)
    print(f"wrote {out_dir/'inflation.csv'}\nwrote {out_dir/'mitigation.csv'}\n"
          f"wrote {out_dir/'summary.json'}\nwrote {out_dir/'summary.md'}")


def _write_md(path, summary, inflation_rows, mit_rows):
    b = summary["baseline_strong_attack"]
    inv = summary["soundness_invariant"]["cert_false_allow_max_over_all_conditions"]
    with open(path, "w") as f:
        f.write("# T2-9 — Abstention-DoS: attacking the price of soundness\n\n")
        f.write("The certified gate trades a **false-allow** attack surface for an **availability / "
                "abstention** one. Prop-4 soundness holds (cert_false_allow=0), but an adversary that "
                "*selects* boundary-seeking inputs (analytic margin |m|~0) can INFLATE the abstention "
                "rate delivered to the human circuit -> an alert-fatigue DoS. Soundness is invariant; "
                "availability is the new axis; a mitigation bounds it.\n\n")
        f.write(f"Pool: real IEEE-CIS balanced set; policy theta_base={THETA_BASE}, delta={DELTA}, "
                f"eps={EPS}. Certified gate = EXACT analytic certificate (allow iff analytic R).\n\n")
        f.write("## 1. Attack — abstention inflation under adversarial input selection\n\n")
        f.write("| strength | abstain_benign | abstain_adv | **inflation** | cfa_benign | cfa_adv |\n")
        f.write("|---:|---:|---:|---:|---:|---:|\n")
        for r in inflation_rows:
            f.write(f"| {r['selection_strength']} | {r['abstain_benign_mean']:.3f}"
                    f"±{r['abstain_benign_std']:.3f} | {r['abstain_adv_mean']:.3f}"
                    f"±{r['abstain_adv_std']:.3f} | **{r['inflation_factor_mean']:.2f}"
                    f"±{r['inflation_factor_std']:.2f}** | {r['cert_false_allow_benign']:.3f} | "
                    f"{r['cert_false_allow_adv']:.3f} |\n")
        f.write(f"\nAt the strongest attack (strength={b['strength']}): abstain "
                f"{b['abstain_benign']:.3f} (benign) -> {b['abstain_adv']:.3f} (adv), "
                f"inflation **{b['inflation_factor']:.2f}x**.\n\n")
        f.write("## 2. Soundness invariant\n\n")
        f.write(f"cert_false_allow over ALL conditions (benign, adversarial, every mitigation) = "
                f"**{inv:.4f}**. The attack costs availability, never safety.\n\n")
        f.write("## 3. Mitigations + cost\n\n")
        f.write("| mitigation | param | abstain_adv_after | inflation_after | cost | cfa |\n")
        f.write("|---|---|---:|---:|---|---:|\n")
        for r in mit_rows:
            f.write(f"| {r['mitigation']} | {r['param']} | {r['abstain_adv_after']:.3f} | "
                    f"{r['inflation_after']:.2f} | {r['cost']} | {r['cert_false_allow']:.3f} |\n")
        f.write("\n**Reads.** (rate_limit) a per-source abstention budget caps the human-circuit load "
                "an adversarial source can inflict -> bounds the inflation, cost = dropped/queued "
                "adversarial volume, NO safety cost. (adaptive_eps) shrinking the certified radius "
                "reclaims boundary records into R (lower abstention) at the price of a *residual "
                "exposure* to attacks between eps' and the full declared radius -- the "
                "abstention-vs-robustness-radius trade. cert_false_allow stays 0 w.r.t. the advertised "
                "radius throughout.\n")


def _maybe_figure(out_dir, inflation_rows, mit_rows):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return
    try:
        fig, ax = plt.subplots(1, 2, figsize=(10, 4))
        s = [r["selection_strength"] for r in inflation_rows]
        infl = [r["inflation_factor_mean"] for r in inflation_rows]
        err = [r["inflation_factor_std"] for r in inflation_rows]
        ax[0].errorbar(s, infl, yerr=err, marker="o")
        ax[0].axhline(1.0, ls="--", c="gray")
        ax[0].set_xlabel("adversarial selection strength")
        ax[0].set_ylabel("abstention inflation factor")
        ax[0].set_title("Attack: abstention-DoS inflation")
        ada = [r for r in mit_rows if r["mitigation"] == "adaptive_eps"]
        eps_x = [float(r["param"].split("=")[1]) for r in ada]
        abst = [r["abstain_adv_after"] for r in ada]
        expo = [float(r["cost"].split("=")[1]) for r in ada]
        ax[1].plot(eps_x, abst, marker="o", label="abstain_adv")
        ax[1].plot(eps_x, expo, marker="s", label="residual exposure (vs full eps)")
        ax[1].set_xlabel("advertised certified radius eps'")
        ax[1].set_title("Mitigation: adaptive-eps trade-off")
        ax[1].legend()
        fig.tight_layout()
        fig.savefig(out_dir / "abstention_dos.png", dpi=110)
        plt.close(fig)
        print(f"wrote {out_dir/'abstention_dos.png'}")
    except Exception as e:
        print(f"[figure skipped] {e}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    ap.add_argument("--n", type=int, default=4000)
    ap.add_argument("--eps", type=float, default=EPS)
    ap.add_argument("--strengths", type=float, nargs="+", default=[0.25, 0.5, 0.75, 1.0])
    ap.add_argument("--out", default=str(OUT_DEFAULT))
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()

    if not IEEE_PATH.exists():
        print(f"[error] IEEE-CIS pool not found at {IEEE_PATH}")
        return

    seeds = args.seeds
    n = args.n
    strengths = args.strengths
    if args.quick:
        seeds = args.seeds[:2] if len(args.seeds) >= 2 else args.seeds
        n = min(n, 800)
        strengths = [0.5, 1.0]

    summary = run(seeds, n, args.eps, strengths, args.out, quick=args.quick)
    print("\n" + json.dumps(summary["baseline_strong_attack"], indent=2))
    return summary


if __name__ == "__main__":
    main()
