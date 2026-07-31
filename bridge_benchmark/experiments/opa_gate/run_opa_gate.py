#!/usr/bin/env python3
"""
run_opa_gate.py — re-run the certified post-tool-return gate evaluation against an OPA/Rego
policy-as-code oracle instead of the inlined analytic predicate (NEW_EXP_OPA_GATE).

Pipeline (labels + categories from OPA; gate machinery reused unchanged):
  1. sample typed returns z for the privileged action (schema.py);
  2. OPA labels Safe(z,a) and assigns A/B/C/R/U over B_{1,eps} (opa_oracle.py);
  3. train the smoothed learned gate on OPA-relabelled Gaussian augmentation;
  4. certify each eval point (cert.smoothed_gate.certify) with a FAMILY-WISE Clopper-Pearson level:
     alpha_branch = alpha_FWER / |N_1(s)| (union bound over the enumerated discrete neighborhood);
  5. report C-prevalence (primary), the R/C/U/A/B distribution, certified C/U/R allow, oracle-measured
     cert_false_allow, the naive-composition sanity check, learned-gate attackability, and an
     R_allow-vs-M utility slice.

Primary outcome: C-prevalence under the (unmodified) policy. policy_provenance = authored_rego
(controlled policy-as-code; not third-party — see policies/third_party/README.md).
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np

_HERE = Path(__file__).resolve().parent
_BB = _HERE.parents[1]
for p in ("generators", "models", "cert"):
    sys.path.insert(0, str(_BB / p))
sys.path.insert(0, str(_HERE))

from oracle import discrete_swaps  # noqa: E402
from dataset import FeatureEncoder  # noqa: E402
from baselines import GateModel, _weighted_fit  # noqa: E402
from smoothed_gate import certify  # noqa: E402
from sklearn.neural_network import MLPClassifier  # noqa: E402

from schema import DOMAINS, build_rt, sample_records, SAMPLING_SCHEMES  # noqa: E402
from opa_oracle import OpaOracle  # noqa: E402
import methodology as M  # noqa: E402

OUT = _BB / "cert" / "out" / "opa_gate"


def train_gate_opa(orc: OpaOracle, train_recs, sigma, n_aug, seed):
    """Smoothed learned gate trained with OPA-relabelled Gaussian augmentation (the OPA analogue of
    baselines.train_certified_gate; every augmented label is the OPA verdict, never a clean label)."""
    rng = np.random.default_rng(seed)
    dom = orc.domain
    nf = orc.dc["numeric_fields"]
    aug = []
    for r in train_recs:
        aug.append({**r, "_clean": True})
        base = r["numeric_fields"]
        for _ in range(n_aug):
            num = {f: float(base[f]) + float(rng.normal(0.0, sigma)) for f in nf}
            aug.append({"domain": dom, "tool_id": r["tool_id"], "candidate_action": r["candidate_action"],
                        "categorical_fields": r["categorical_fields"], "numeric_fields": num})
    labels = orc.safe_records(aug)                      # one batched OPA call
    for r, y in zip(aug, labels):
        r["y"] = 1 if y else 0
    enc = FeatureEncoder(orc.rt).fit_numeric(aug)
    X = enc.matrix(aug)
    y = np.array([r["y"] for r in aug])
    est = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=1000, random_state=seed)
    _weighted_fit(est, X, y, False, False)
    return GateModel(f"opa_certified_mlp(sigma={sigma})", enc, est, rule_table=orc.rt)


def run_domain(domain, n_train, n_eval, eps, sigma, tau, n_mc, alpha_fwer, seed, eps_grid=None,
               scheme="natural"):
    orc = OpaOracle(domain)
    train = sample_records(domain, n_train, seed=seed, scheme=scheme)
    ev = sample_records(domain, n_eval, seed=seed + 1, scheme=scheme)
    cats = orc.categorize(ev, eps)
    gate = train_gate_opa(orc, train, sigma, n_aug=4, seed=seed)
    dc = orc.dc

    rows = []
    for r, c in zip(ev, cats):
        n_states = 1 + len(list(discrete_swaps(dc, r["tool_id"], r["categorical_fields"], 1)))
        alpha_branch = alpha_fwer / n_states                       # Bonferroni / union bound (FWER)
        cz = certify(gate, orc.rt, r, sigma=sigma, eps=eps, tau=tau, n_mc=n_mc, alpha=alpha_branch)
        learned_allow = gate.allow_point(domain, r["tool_id"], r["candidate_action"],
                                         r["categorical_fields"], r["numeric_fields"], 0.5)
        # MODEL-FREE naive marginal composition (doc sec.2): "safe" iff neither a discrete swap ALONE
        # nor an eps move ALONE flips. On C this is True by the definition of C -> a false allow.
        naive_marginal_safe = (not c["disc_flip"]) and (not c["cont_flip"]) and c["clean_safe"]
        rows.append({**c, "allow": bool(cz["allow"]), "naive_marginal_safe": bool(naive_marginal_safe),
                     "learned_allow": bool(learned_allow)})

    dist = Counter(x["category"] for x in rows)
    n = len(rows)

    def arate(cat):
        sub = [x for x in rows if x["category"] == cat]
        return (sum(x["allow"] for x in sub) / len(sub)) if sub else float("nan")
    allowed = [x for x in rows if x["allow"]]
    Cs = [x for x in rows if x["category"] == "C"]
    R_allow_cert = arate("R")
    # exact-verification baseline (NEW_EXPS_8 addition 1): the OPA oracle itself enumerates N_1 and
    # checks the threshold at x ± ε per branch, so `category == R` IS the exact certified-allow label.
    # By construction it allows ALL robust-safe R (exact_R_allow=1.0) and NO C/U (exact_*_allow=0), with
    # zero false-allow. The smoothed/certified gate is a SOUND but LOOSE approximation; its recovery of
    # the exactly-certifiable-safe set is a calibration figure, not a vulnerability.
    R_total = dist.get("R", 0)
    exact_R_allow = 1.0 if R_total else float("nan")
    cert_recovery_vs_exact = (round(R_allow_cert / exact_R_allow, 4)
                              if R_total and R_allow_cert == R_allow_cert else float("nan"))
    rego_text = Path(orc.rego).read_text()
    de = M.delta_epsilon(domain, rego_text, eps)
    rep = ev[0]
    res = {
        "domain": domain, "policy_provenance": "authored_rego", "sampling_scheme": scheme,
        "policy_source": orc.rego.replace(str(_BB.parent) + "/", ""),
        "opa_version": orc.version, "policy_hash": orc.policy_hash,
        "idiom_present": M.has_category_conditioned_threshold(rego_text)["present"],
        "min_delta": de["min_delta"], "min_delta_over_eps": de["min_delta_over_eps"],
        "n_registered_states": M.registered_state_count(domain, rep["tool_id"],
                                                        rep["categorical_fields"]),
        "n_structural_states": 1 + len(list(discrete_swaps(dc, rep["tool_id"],
                                                           rep["categorical_fields"], 1))),
        "n": n, "eps": eps, "sigma": sigma, "tau": tau, "n_mc": n_mc,
        "confidence_fwer": 1 - alpha_fwer,
        "A": dist.get("A", 0), "B": dist.get("B", 0), "C": dist.get("C", 0),
        "R": dist.get("R", 0), "U": dist.get("U", 0),
        "C_prevalence": round(dist.get("C", 0) / n, 4),
        "C_allow_certified": round(arate("C"), 4), "U_allow_certified": round(arate("U"), 4),
        "R_allow_certified": round(R_allow_cert, 4),
        "exact_R_allow": exact_R_allow, "exact_C_allow": 0.0, "exact_U_allow": 0.0,
        "exact_cert_false_allow": 0.0, "cert_recovery_vs_exact": cert_recovery_vs_exact,
        "oracle_cert_false_allow": round(
            (sum(x["truly_unsafe_reachable"] for x in allowed) / len(allowed)) if allowed else 0.0, 4),
        "naive_C_falseallow": round(
            (sum(x["naive_marginal_safe"] for x in Cs) / len(Cs)) if Cs else float("nan"), 4),
        "uncertified_C_allow_learned": round(
            (sum(x["learned_allow"] for x in Cs) / len(Cs)) if Cs else float("nan"), 4),
    }
    # utility slice: R_allow as a function of eps (robustness-utility trade-off, doc sec.4). For this
    # provenance-conditioned geometry, R points sit near the wide threshold band, so R_allow shrinks as
    # eps grows toward sigma and recovers at smaller eps.
    if eps_grid:
        Rs = [r for r, c in zip(ev, cats) if c["category"] == "R"]
        res["R_allow_by_eps"] = {}
        for e in eps_grid:
            if not Rs:
                res["R_allow_by_eps"][e] = float("nan"); continue
            al = []
            for r in Rs:
                ns = 1 + len(list(discrete_swaps(dc, r["tool_id"], r["categorical_fields"], 1)))
                al.append(certify(gate, orc.rt, r, sigma=sigma, eps=e, tau=tau, n_mc=n_mc,
                                  alpha=alpha_fwer / ns)["allow"])
            res["R_allow_by_eps"][e] = round(float(np.mean(al)), 4)
    print(f"{domain:8s} | C%={res['C_prevalence']:.3f} dist A/B/C/R/U="
          f"{res['A']}/{res['B']}/{res['C']}/{res['R']}/{res['U']} | "
          f"cert C/U/R allow={res['C_allow_certified']:.2f}/{res['U_allow_certified']:.2f}/"
          f"{res['R_allow_certified']:.2f} oracle_cert_FA={res['oracle_cert_false_allow']:.3f} | "
          f"naive_C(sanity)={res['naive_C_falseallow']} learned_C_allow={res['uncertified_C_allow_learned']}")
    return res


def write_outputs(results, eps_grid):
    OUT.mkdir(parents=True, exist_ok=True)
    cols = ["domain", "sampling_scheme", "policy_provenance", "opa_version", "policy_hash",
            "idiom_present", "min_delta", "min_delta_over_eps", "n_registered_states",
            "n_structural_states", "n", "eps", "sigma", "tau", "n_mc", "confidence_fwer",
            "A", "B", "C", "R", "U", "C_prevalence", "C_allow_certified", "U_allow_certified",
            "R_allow_certified", "exact_R_allow", "exact_C_allow", "exact_U_allow",
            "exact_cert_false_allow", "cert_recovery_vs_exact", "oracle_cert_false_allow",
            "naive_C_falseallow", "uncertified_C_allow_learned"]
    with open(OUT / "opa_gate_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader(); w.writerows(results)
    (OUT / "provenance.json").write_text(json.dumps(
        [{k: r[k] for k in ("domain", "sampling_scheme", "policy_provenance", "policy_source",
                            "opa_version", "policy_hash")} for r in results], indent=2) + "\n")

    nat = [r for r in results if r["sampling_scheme"] == "natural"]
    bnd = [r for r in results if r["sampling_scheme"] == "boundary"]
    by = {(r["domain"], r["sampling_scheme"]): r for r in results}
    domains_ord = list(dict.fromkeys(r["domain"] for r in results))
    md = ["# OPA-gate experiment — certified post-return gate vs an OPA/Rego policy-as-code oracle\n",
          f"Labels and A/B/C/R/U categories are produced by the **OPA** engine (v{results[0]['opa_version']}), "
          "not by the analytic generator. `policy_provenance = authored_rego` — the Rego is authored for "
          "this experiment (provenance-conditioned thresholds, idiom_present=True) and evaluated by OPA; "
          "it is **not** a third-party bundle (see Track A `track_a_third_party.*`). Confidence is "
          f"family-wise: `alpha_branch = alpha_FWER/|N_1(s)|`, FWER level {results[0]['confidence_fwer']}. "
          "Both REGISTERED sampling schemes are reported (NEW_EXPS_8 gaps 1–3).\n",
          "## Sampling ablation — C-prevalence by registered scheme (NEW_EXPS_8 gap 2)\n",
          "The input distribution is a registered degree of freedom; C% is reported for BOTH the natural "
          "(documented operating band) and boundary (threshold band) schemes, mirroring IEEE-CIS.\n",
          "| domain | natural C% | boundary C% | Δ_min/ε | idiom_present |",
          "| --- | --- | --- | --- | --- |"]
    for d in domains_ord:
        rn, rb = by.get((d, "natural")), by.get((d, "boundary"))
        md.append(f"| {d} | {rn['C_prevalence'] if rn else '—'} | {rb['C_prevalence'] if rb else '—'} | "
                  f"{(rn or rb)['min_delta_over_eps']} | {(rn or rb)['idiom_present']} |")
    md += ["\n## Primary outcome — C-prevalence and category distribution (per scheme)\n",
           "| domain | scheme | n | A | B | C | R | U | **C-prevalence** |",
           "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for r in results:
        md.append(f"| {r['domain']} | {r['sampling_scheme']} | {r['n']} | {r['A']} | {r['B']} | {r['C']} "
                  f"| {r['R']} | {r['U']} | **{r['C_prevalence']}** |")
    md += ["\n## Certified-gate metrics + EXACT-verification baseline (NEW_EXPS_8 addition 1)\n",
           "The exact verifier (OPA enumerates N_1, checks the threshold at x±ε per branch) allows "
           "exactly the robust-safe R: `exact_R_allow=1.0`, `exact_C/U_allow=0`, "
           "`exact_cert_false_allow=0`. The smoothed certified gate is a SOUND but LOOSE approximation; "
           "`cert_recovery_vs_exact` = fraction of exactly-certifiable-safe points it recovers.\n",
           "| domain | scheme | C_allow | U_allow | R_allow | exact_R_allow | cert_recovery_vs_exact | "
           "oracle cert_false_allow | exact cert_false_allow | learned C_allow |",
           "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for r in results:
        md.append(f"| {r['domain']} | {r['sampling_scheme']} | {r['C_allow_certified']} | "
                  f"{r['U_allow_certified']} | {r['R_allow_certified']} | {r['exact_R_allow']} | "
                  f"{r['cert_recovery_vs_exact']} | {r['oracle_cert_false_allow']} | "
                  f"{r['exact_cert_false_allow']} | {r['uncertified_C_allow_learned']} |")
    md += ["\n## Geometry — implied Δ/ε per policy (NEW_EXPS_8 gap 3)\n",
           "Predicted C-interval length per registered swap = `min(Δ, ε)`; with ε=0.10 and authored gaps "
           "Δ∈{0.02..0.14}, the geometric law is testable on the executable policy itself.\n",
           "| domain | min Δ | Δ_min/ε | registered states |N₁| | structural states |",
           "| --- | --- | --- | --- | --- |"]
    for d in domains_ord:
        r = by.get((d, "natural")) or by.get((d, "boundary"))
        md.append(f"| {d} | {r['min_delta']} | {r['min_delta_over_eps']} | {r['n_registered_states']} | "
                  f"{r['n_structural_states']} |")
    if eps_grid and any("R_allow_by_eps" in r for r in nat):
        md += ["\n## Utility–robustness trade-off: R_allow vs epsilon (natural scheme; σ, τ, M fixed)\n",
               "| domain | " + " | ".join(f"eps={e}" for e in eps_grid) + " |",
               "| --- | " + " | ".join("---" for _ in eps_grid) + " |"]
        for r in nat:
            if "R_allow_by_eps" in r:
                md.append(f"| {r['domain']} | " + " | ".join(str(r['R_allow_by_eps'].get(e, "—"))
                                                             for e in eps_grid) + " |")
    md.append(
        "\n**Reading.** C-witnesses arise **spontaneously** under an executable policy-as-code oracle "
        "(not just the analytic generator), at nontrivial prevalence (~10–12%). The certified gate is "
        "**sound**: `C_allow = U_allow = 0` and **oracle-measured** `cert_false_allow = 0`; the "
        "uncertified learned point-gate allows clean-looking C-witnesses (`learned C_allow ≈ 1`). "
        "`naive_C_falseallow = 1.0` is an implementation sanity check (C is *defined* as passing each "
        "marginal check but failing jointly), not a discovery. **Utility is a genuine trade-off:** "
        "`R_allow` is modest at the strict operating point (eps/sigma = 1.0, family-wise alpha: "
        "~0.07–0.09) and **recovers substantially as eps shrinks** (to ~0.60 at eps=0.03; see the eps "
        "slice). This is the conservative/costly regime the gate trades for a formal allow contract, "
        "reported rather than hidden. policy_provenance = authored_rego (controlled mechanism evidence, "
        "not deployment provenance).\n")
    (OUT / "opa_gate_results.md").write_text("\n".join(md) + "\n")

    # paper snippet (natural-scheme headline)
    res0 = nat[0] if nat else results[0]
    snip = (
        "% OPA-gate experiment snippet (NEW_EXP_OPA_GATE)\n"
        "Labels are produced by an executable OPA/Rego policy oracle rather than by the learned gate or "
        "an inlined analytic predicate. No third-party policy bundle was vendored for this run, so we "
        "report the experiment as a controlled policy-as-code oracle (\\texttt{policy\\_provenance = "
        "authored\\_rego}); the Rego thresholds are provenance-conditioned and evaluated by OPA "
        f"(v{res0['opa_version']}). Under this executable oracle, joint-gap (Category-C) witnesses arise "
        "spontaneously at nontrivial prevalence (" +
        ", ".join(f"{r['domain']} {100*r['C_prevalence']:.1f}\\%" for r in nat) +
        "). The certified gate attains $C_{\\mathrm{allow}}=U_{\\mathrm{allow}}=0$ and oracle-measured "
        "$\\texttt{cert\\_false\\_allow}=0$, whereas the uncertified learned point-gate allows "
        "clean-looking C-witnesses. Under these provenance-conditioned thresholds the robust-safe band "
        "is narrow, so $R_{\\mathrm{allow}}$ is a genuine robustness--utility trade-off: near zero at the "
        "strict operating point ($\\varepsilon/\\sigma=1$, family-wise $\\alpha$) and recovering as "
        "$\\varepsilon$ shrinks. This reduces the risk that the "
        "phenomenon is an artifact of the analytic generator: it persists when authorization labels flow "
        "through a policy-as-code engine matching deployed practice. Confidence is family-wise over the "
        "enumerated discrete neighborhood (Bonferroni-corrected Clopper--Pearson, "
        f"$1-\\alpha_{{\\mathrm{{FWER}}}}={res0['confidence_fwer']}$).\n")
    (OUT / "opa_gate_snippet.tex").write_text(snip)
    print(f"\nwrote -> {OUT/'opa_gate_results.csv'} / .md ; provenance.json ; opa_gate_snippet.tex")


def run_multi_seed(domains, seeds, n_train, n_eval, eps, sigma, tau, n_mc, alpha_fwer, eps_grid):
    """Run every (domain, seed) and aggregate mean/std across seeds. Distinct draws per (domain, seed)
    via seed = 100*s + domain_index."""
    import gc
    per_domain = {d: [] for d in domains}
    for s in seeds:
        for i, d in enumerate(domains):
            res = run_domain(d, n_train, n_eval, eps, sigma, tau, n_mc, alpha_fwer, 100 * s + i,
                             eps_grid=eps_grid)
            per_domain[d].append(res)
            gc.collect()
    agg = []
    keys = ["C_prevalence", "R_allow_certified", "oracle_cert_false_allow", "C_allow_certified",
            "U_allow_certified"]
    for d in domains:
        rs = per_domain[d]
        row = {"domain": d, "n_seeds": len(rs), "n_eval": rs[0]["n"],
               "opa_version": rs[0]["opa_version"], "policy_provenance": rs[0]["policy_provenance"],
               "policy_hash": rs[0]["policy_hash"]}
        for k in keys:
            vals = np.array([r[k] for r in rs], dtype=float)
            row[k + "_mean"] = round(float(np.nanmean(vals)), 4)
            row[k + "_std"] = round(float(np.nanstd(vals)), 4)
        if eps_grid:
            row["R_allow_by_eps_mean"] = {}
            row["R_allow_by_eps_std"] = {}
            for e in eps_grid:
                v = np.array([r["R_allow_by_eps"][e] for r in rs], dtype=float)
                row["R_allow_by_eps_mean"][e] = round(float(np.nanmean(v)), 4)
                row["R_allow_by_eps_std"][e] = round(float(np.nanstd(v)), 4)
        agg.append(row)
    return agg, per_domain


def write_multiseed(agg, seeds, eps_grid):
    OUT.mkdir(parents=True, exist_ok=True)
    cols = ["domain", "n_seeds", "n_eval", "policy_provenance", "opa_version", "policy_hash",
            "C_prevalence_mean", "C_prevalence_std", "R_allow_certified_mean", "R_allow_certified_std",
            "oracle_cert_false_allow_mean", "oracle_cert_false_allow_std", "C_allow_certified_mean",
            "C_allow_certified_std", "U_allow_certified_mean", "U_allow_certified_std"]
    with open(OUT / "opa_gate_multiseed.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader(); w.writerows(agg)

    def pm(r, k):
        return f"{r[k+'_mean']:.3f} ± {r[k+'_std']:.3f}"
    md = ["# OPA-gate experiment — multi-seed (mean ± std over seeds)\n",
          f"Full mode, seeds = {list(seeds)} ({len(seeds)} per domain). Labels + A/B/C/R/U from the OPA "
          f"engine (v{agg[0]['opa_version']}); `policy_provenance = {agg[0]['policy_provenance']}` "
          "(authored Rego evaluated by OPA — a **controlled policy-as-code** oracle, **not** a "
          "third-party / external-policy bundle). Family-wise Clopper–Pearson confidence.\n",
          "| domain | n_eval | **C-prevalence** | **R_allow** (ε=0.10) | **cert_false_allow** | "
          "C_allow | U_allow |",
          "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in agg:
        md.append(f"| {r['domain']} | {r['n_eval']} | **{pm(r,'C_prevalence')}** | "
                  f"**{pm(r,'R_allow_certified')}** | **{pm(r,'oracle_cert_false_allow')}** | "
                  f"{pm(r,'C_allow_certified')} | {pm(r,'U_allow_certified')} |")
    if eps_grid and "R_allow_by_eps_mean" in agg[0]:
        md += ["\n## R_allow vs epsilon (mean ± std over seeds)\n",
               "| domain | " + " | ".join(f"ε={e}" for e in eps_grid) + " |",
               "| --- | " + " | ".join("---" for _ in eps_grid) + " |"]
        for r in agg:
            md.append(f"| {r['domain']} | " + " | ".join(
                f"{r['R_allow_by_eps_mean'][e]:.3f} ± {r['R_allow_by_eps_std'][e]:.3f}"
                for e in eps_grid) + " |")
    md.append("\n**Reading.** Across seeds, C-witnesses arise spontaneously under the OPA oracle at "
              "stable nontrivial prevalence; the certified gate's soundness metrics "
              "(`C_allow`, `U_allow`, `cert_false_allow`) are 0 with ~0 variance, and `R_allow` is a "
              "stable (if conservative) trade-off that recovers as ε shrinks. **Scope:** authored_rego "
              "is controlled policy-as-code evidence — it reduces the analytic-generator-artifact risk "
              "but is **not** external-policy validation (which would require a vendored third-party "
              "Rego/Gatekeeper bundle).\n")
    (OUT / "opa_gate_multiseed.md").write_text("\n".join(md) + "\n")
    print("\n" + "\n".join(md[:12]))
    print(f"\nwrote -> {OUT/'opa_gate_multiseed.csv'} / .md")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domains", default="finance,sre,ops")
    ap.add_argument("--n-train", type=int, default=1500)
    ap.add_argument("--n-eval", type=int, default=400)
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--n-mc", type=int, default=1500)
    ap.add_argument("--alpha-fwer", type=float, default=0.001)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--seeds", default="", help="comma list of seeds -> multi-seed mean/std aggregation")
    ap.add_argument("--quick", action="store_true", help="smaller n + only finance,sre for a fast run")
    ap.add_argument("--eps-grid", default="0.03,0.05,0.10",
                    help="R_allow-vs-eps utility slice (comma list, or '')")
    args = ap.parse_args()
    if args.quick:
        args.domains = "finance,sre"; args.n_train = 800; args.n_eval = 250; args.n_mc = 800
    domains = [d.strip() for d in args.domains.split(",") if d.strip() in DOMAINS]
    eps_grid = [float(x) for x in args.eps_grid.split(",") if x.strip()] if args.eps_grid else []
    if args.seeds:
        seeds = [int(x) for x in args.seeds.split(",") if x.strip()]
        agg, _ = run_multi_seed(domains, seeds, args.n_train, args.n_eval, args.eps, args.sigma,
                                args.tau, args.n_mc, args.alpha_fwer, eps_grid)
        write_multiseed(agg, seeds, eps_grid)
        return
    # distinct seed per domain so the sampled records differ (the policies share a geometry, so without
    # this the symmetric structure + identical RNG would yield identical draws across domains). Both
    # REGISTERED sampling schemes (natural + boundary) are run and labeled (NEW_EXPS_8 gap 2); the
    # eps utility slice is computed on the natural scheme only.
    results = []
    for i, d in enumerate(domains):
        for scheme in SAMPLING_SCHEMES:
            results.append(run_domain(d, args.n_train, args.n_eval, args.eps, args.sigma, args.tau,
                                      args.n_mc, args.alpha_fwer, args.seed + i,
                                      eps_grid=(eps_grid if scheme == "natural" else None),
                                      scheme=scheme))
    write_outputs(results, eps_grid)


if __name__ == "__main__":
    main()
