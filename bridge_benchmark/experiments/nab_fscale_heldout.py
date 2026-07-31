#!/usr/bin/env python3
"""M3 — fscale held-out selection for the NAB Table-5 row (S29 protocol on NAB).

Motivation: The NAB Table-5 headline row
(R_allow=100%, fscale=4) fixed the Lipschitz numeric-block scale `fscale` on the SAME
records it is reported on — outcome-conditioned hyperparameter selection. S29 already
resolved this for the synthetic and OPA tracks; this run extends the identical protocol
to NAB, defending a number already in the paper.

Protocol (S29 verbatim, on NAB): split the balanced cert set into a SELECTION half and an
EVAL half; select fscale by the honest rule — **largest fscale with cert_false_allow=0 on
the SELECTION half** — then re-report cert_false_allow / R_allow / clean-acc on the untouched
EVAL half. Grid {2,3,4,6}, 3 seeds, ε=0.10, δ=0.08. Also runs the selection at d=2 to note
the sound value there (the d≥2 threat-model row).

Deterministic 1-Lipschitz orthogonal backend (the preferred primary; no MC). The gate trained
on an fscale-scaled encoder is fscale-Lipschitz in the RAW ε-ball, so the margin certificate
stays EXACTLY sound with L = _LIP_CERT_L_MULT·fscale·CLAIMED_L. Reuses the verified NAB path in
`second_real_dataset.py`. Needs torch/orthogonium + GPU.

Kill rule (honest): if no grid value is sound on the EVAL half → demote the NAB row to RS-only.

Outputs (gitignored cert/out):
    cert/out/nab_fscale_heldout.json
    cert/out/nab_fscale_heldout.md
"""
from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import second_real_dataset as S  # noqa: E402

OUT = _HERE.parent / "cert" / "out"
EPS = 0.10
DELTA = 0.08
FSCALE_GRID = [2.0, 3.0, 4.0, 6.0]


def _cert_false_allow_and_R(model, enc, rt, cert_recs, cert_L, eps, d):
    """Deterministic Lipschitz cert over B_{d,eps}: (R_allow, cert_false_allow, n_allowed, n_R)."""
    r_flags, n_allowed, false_allow = [], 0, 0
    for r in cert_recs:
        allow = S.certify_lip(model, enc, rt, r, eps=eps, L=cert_L)["allow"]
        if r["category"] == "R":
            r_flags.append(1 if allow else 0)
        if allow:
            n_allowed += 1
            unsafe = (r["y"] == 0 or S.joint_reachable_unsafe(
                r, r["candidate_action"], rt, d, eps)["reachable"])
            if unsafe:
                false_allow += 1
    return {"R_allow": float(np.mean(r_flags)) if r_flags else float("nan"),
            "cert_false_allow": (false_allow / n_allowed) if n_allowed else 0.0,
            "n_allowed": n_allowed, "n_R": len(r_flags)}


def _clean_acc(model, enc, recs):
    pred = np.array([1 if S.lip_pointwise_allow(model, enc, r) else 0 for r in recs])
    y = np.array([r["y"] for r in recs])
    return float(np.mean(pred == y)) if len(recs) else float("nan")


def _balanced_cert(recs, n_cert):
    return sum(([r for r in recs if r["category"] == c][:n_cert] for c in S.CATS), [])


def _split_cert(test, n_cert):
    """Build SELECTION and EVAL cert subsets that are BOTH balanced across categories, by interleaving
    each category's records (even idx → selection, odd idx → eval). Guarantees R present in both halves
    (a plain test[:half] slice is not stratified and can starve the selection half of R records)."""
    sel, ev = [], []
    for c in S.CATS:
        recs_c = [r for r in test if r["category"] == c][: 2 * n_cert]
        sel += recs_c[0::2]
        ev += recs_c[1::2]
    return sel, ev


def run_seed(df, seed, *, fscales, eps, delta, theta_q, sigma, n_records, train_cap,
             n_cert, lip_epochs, d_extra):
    from collections import Counter
    split = S.adp.assign_split(df, seed)
    df_gate = df[split == "gate_pool"]
    cpu = np.clip(df_gate["value"].astype(float).to_numpy() / 100.0, 0.0, 1.0)
    theta_base = min(0.95, max(0.05, float(np.quantile(cpu, theta_q)) if len(cpu) else 0.5))
    rt = S.pol.build_rule_table(theta_base, delta)

    natural = S.build_candidates(df_gate, theta_base=theta_base, delta=delta, eps=eps, seed=seed)
    balanced = S._balanced_select(natural, n_records)
    internal = S.to_internal(balanced, rt, eps, d=1)
    train, _val, test = S.stratified_split(internal)

    # SELECTION / EVAL split of the untouched test records — both balanced across categories
    sel_cert, eval_cert = _split_cert(test, n_cert)
    eval_clean = [r for r in test if r not in sel_cert]   # clean-acc on the non-selection records
    norc = S._NabOracle(rt, S.pol.DOMAIN, S.pol.ACTION)

    def _train(fs):
        enc = S.scaled_encoder(rt, fs)
        gamma = round(2.0 * fs * eps, 3)          # γ tied to the cert-threshold scale (2·fscale·ε)
        model = S.train_lipgate(norc, enc, train[:train_cap], variant=S._LIP_VARIANT,
                                epochs=lip_epochs, lam_margin=S._LIP_LAM_MARGIN, gamma=gamma,
                                sigma=sigma, seed=seed, n_aug=S._LIP_N_AUG)
        return model, enc, S._LIP_CERT_L_MULT * fs * S.CLAIMED_L

    grid, trained = [], {}
    for fs in fscales:
        model, enc, cert_L = _train(fs)
        trained[fs] = (model, enc, cert_L)
        m = _cert_false_allow_and_R(model, enc, rt, sel_cert, cert_L, eps, d=1)
        grid.append({"fscale": fs, "sel_cert_false_allow": round(m["cert_false_allow"], 5),
                     "sel_R_allow": round(m["R_allow"], 4)})

    sound = [g["fscale"] for g in grid if g["sel_cert_false_allow"] == 0.0]
    fs_star = max(sound) if sound else min(fscales)
    model, enc, cert_L = trained[fs_star]
    ev1 = _cert_false_allow_and_R(model, enc, rt, eval_cert, cert_L, eps, d=1)
    acc = _clean_acc(model, enc, eval_clean)

    # d=2 note: which fscale stays sound on the EVAL half at d=2 (reuse the trained models)
    d2 = []
    for fs in fscales:
        m2, e2, cl2 = trained[fs]
        mm = _cert_false_allow_and_R(m2, e2, rt, eval_cert, cl2, eps, d=d_extra)
        d2.append({"fscale": fs, "eval_cert_false_allow_d2": round(mm["cert_false_allow"], 5),
                   "eval_R_allow_d2": round(mm["R_allow"], 4)})
    sound_d2 = [x["fscale"] for x in d2 if x["eval_cert_false_allow_d2"] == 0.0]
    fs_star_d2 = max(sound_d2) if sound_d2 else None

    row = {"seed": seed, "theta_base": round(theta_base, 6), "selection_grid": grid,
           "sel_sound_fscales": sound, "selected_fscale_d1": fs_star,
           "eval_cert_false_allow_d1": round(ev1["cert_false_allow"], 5),
           "eval_R_allow_d1": round(ev1["R_allow"], 4), "eval_clean_acc": round(acc, 4),
           "eval_sound_d1": ev1["cert_false_allow"] == 0.0,
           "d2_grid": d2, "sound_fscales_d2": sound_d2, "selected_fscale_d2": fs_star_d2}
    print(f"[nab seed={seed}] fscale*(d1)={fs_star} (sel-sound {sound}) → eval cfa={row['eval_cert_false_allow_d1']} "
          f"R={row['eval_R_allow_d1']} acc={row['eval_clean_acc']} | d2 sound fscales={sound_d2}")
    return row


def run(seeds, fscales, eps, delta, quick, out_prefix, d_extra=2):
    if not S._LIP_OK:
        print(f"[error] Lipschitz backend unavailable: {S._LIP_ERR}")
        return None
    df = S.adp.load_raw(max_rows=40000 if quick else None)
    n_records = 2000 if quick else 6000
    train_cap = 4000 if quick else 12000
    n_cert = 25 if quick else 40
    lip_epochs = 500 if quick else 2000

    per_seed = [run_seed(df, s, fscales=fscales, eps=eps, delta=delta, theta_q=0.70,
                         sigma=0.10, n_records=n_records, train_cap=train_cap, n_cert=n_cert,
                         lip_epochs=lip_epochs, d_extra=d_extra) for s in seeds]

    all_sound = all(r["eval_sound_d1"] for r in per_seed)
    binds = any(len(r["sel_sound_fscales"]) < len(fscales) for r in per_seed)
    eval_cfa_max = max(r["eval_cert_false_allow_d1"] for r in per_seed)
    R_mean = float(np.nanmean([r["eval_R_allow_d1"] for r in per_seed]))
    d2_sound_all = [r["selected_fscale_d2"] for r in per_seed]

    if all_sound:
        verdict = (f"SELECTION OBJECTION RESOLVED on NAB: the held-out-selected fscale "
                   f"(d=1 selections {[r['selected_fscale_d1'] for r in per_seed]}) keeps "
                   f"cert_false_allow=0 on the untouched EVAL half for every seed (max {eval_cfa_max}), "
                   f"eval R_allow mean {R_mean:.3f}"
                   + (f"; the rule genuinely EXCLUDES an unsound fscale on ≥1 seed's SELECTION half "
                      f"(binds), so the Table-5 NAB fscale is not outcome-conditioned."
                      if binds else
                      f"; no soundness cliff appears in the grid on NAB (every fscale is sound on the "
                      f"selection half), so the rule does not bind but soundness generalizes to eval.")
                   + f" d=2 note: sound fscales per seed {d2_sound_all} (the d≥2 threat-model operating point).")
    else:
        verdict = (f"KILL TRIGGERED: EVAL cert_false_allow>0 for the held-out-selected fscale on ≥1 seed "
                   f"(max {eval_cfa_max}). Per the M3 kill rule, demote the NAB Table-5 row to RS-only.")

    payload = {
        "experiment": "M3 = R2 — NAB fscale held-out selection (S29 protocol on NAB)",
        "eps": eps, "delta": delta, "fscale_grid": fscales,
        "seeds": list(seeds), "d": 1, "d_extra": d_extra, "quick": quick,
        "selection_rule": "largest fscale with cert_false_allow==0 on the SELECTION half; report on EVAL half",
        "per_seed": per_seed, "all_eval_sound_d1": all_sound, "selection_rule_binds": binds,
        "eval_cert_false_allow_max_d1": eval_cfa_max, "eval_R_allow_mean_d1": round(R_mean, 4),
        "selected_fscales_d1": [r["selected_fscale_d1"] for r in per_seed],
        "sound_fscales_d2_per_seed": d2_sound_all, "verdict": verdict,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{out_prefix}.json").write_text(json.dumps(payload, indent=2))
    _write_md(OUT / f"{out_prefix}.md", payload)
    print(f"\nVERDICT: {verdict}")
    print(f"wrote -> {OUT/(out_prefix+'.json')}")
    return payload


def _write_md(path, p):
    with open(path, "w") as f:
        f.write("# M3 = R2 — NAB fscale held-out selection (S29 protocol on NAB)\n\n")
        f.write(f"Rule: **{p['selection_rule']}**. "
                f"ε={p['eps']}, δ={p['delta']}, grid={p['fscale_grid']}, seeds={p['seeds']}, d=1 "
                f"(+d={p['d_extra']} note).\n\n")
        f.write("| seed | selection grid (d=1) | fscale* (d1) | eval cfa (d1) | eval R_allow (d1) | "
                "eval acc | sound | fscale* (d2) |\n")
        f.write("|--:|---|--:|--:|--:|--:|:--:|--:|\n")
        for r in p["per_seed"]:
            g = " ; ".join(f"fs{x['fscale']}:cfa{x['sel_cert_false_allow']}/R{x['sel_R_allow']}"
                           for x in r["selection_grid"])
            f.write(f"| {r['seed']} | {g} | {r['selected_fscale_d1']} | {r['eval_cert_false_allow_d1']} | "
                    f"{r['eval_R_allow_d1']} | {r['eval_clean_acc']} | "
                    f"{'Y' if r['eval_sound_d1'] else 'N'} | {r['selected_fscale_d2']} |\n")
        f.write(f"\nOverall EVAL cert_false_allow max (d=1) **{p['eval_cert_false_allow_max_d1']}**, "
                f"eval R_allow mean **{p['eval_R_allow_mean_d1']}**, all eval sound "
                f"**{p['all_eval_sound_d1']}**, selection rule binds **{p['selection_rule_binds']}**.\n\n")
        f.write(f"**Verdict.** {p['verdict']}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", default="0,1,2")
    ap.add_argument("--fscales", default=",".join(str(x) for x in FSCALE_GRID))
    ap.add_argument("--eps", type=float, default=EPS)
    ap.add_argument("--delta", type=float, default=DELTA)
    ap.add_argument("--d-extra", type=int, default=2)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default="nab_fscale_heldout")
    a = ap.parse_args()
    seeds = [int(s) for s in a.seeds.split(",") if s.strip()]
    fscales = [float(x) for x in a.fscales.split(",") if x.strip()]
    run(seeds, fscales, a.eps, a.delta, a.quick, a.out, d_extra=a.d_extra)


if __name__ == "__main__":
    main()
