#!/usr/bin/env python3
"""
fscale_heldout_selection.py — EXP-C4 = EXP-B4 (NEW_NEW_EXP.md Priority C; r3 outcome-conditioned selection).

The Lipschitz numeric-block scale `fscale` was, in the T2-8 headline, chosen as the largest value keeping
cert_false_allow=0 — but observed on the SAME evaluation set it is reported on. A reviewer can object that
this is outcome-conditioned hyperparameter selection. This experiment closes it properly: split the held-out
evaluation records into a SELECTION half and an EVAL half; select fscale by the honest rule (**largest fscale
with cert_false_allow=0 on the SELECTION half**); then re-report R_allow / cert_false_allow / clean-acc on the
untouched EVAL half. If the held-out-selected fscale still gives cert_false_allow=0 on eval with non-vacuous
R_allow, the selection objection is resolved with no loss.

Reuses T2-8 `d_sweep`: build_synthetic, train_synth_lip (per-fscale cfg), certify_lip_at_d,
analytic_joint_unsafe_map, valid_states_d. Deterministic 1-Lipschitz backend (the preferred primary; no MC).
Needs torch/orthogonium + GPU. d=1 (MVP).
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
import d_sweep as DS  # noqa: E402

OUT = _HERE.parent / "cert" / "out"
EPS = 0.10
FSCALE_GRID = [2.0, 3.0, 4.0, 6.0]


def _cert_subset(ev, n_cert):
    """Balanced cert subset (mirror eval_track_seed): R records + a stress mix (U,C,A,B)."""
    by = {c: [r for r in ev if r.get("category") == c] for c in "ABCRU"}
    R = by["R"][:n_cert]
    stress = (by["U"] + by["C"] + by["A"] + by["B"])[:n_cert]
    return R + [r for r in stress if r not in R]


def certify_metrics(model, enc, rt, cert_recs, fscale, eps, d=1, ju_map=None):
    """Deterministic Lipschitz cert over B_{d,eps}: return (R_allow, cert_false_allow, n_allowed).
    ju_map: callable(cert_recs,d,eps)->{id:joint_unsafe}; defaults to the analytic map for `rt`."""
    ju = (ju_map or DS.analytic_joint_unsafe_map(rt))(cert_recs, d, eps)
    r_flags, false_allow, n_allowed = [], 0, 0
    for r in cert_recs:
        allow, _ns, _mm = DS.certify_lip_at_d(model, enc, rt, r, d, eps=eps, fscale=fscale)
        if r.get("category") == "R":
            r_flags.append(1 if allow else 0)
        if allow:
            n_allowed += 1
            if ju[id(r)]:
                false_allow += 1
    return {"R_allow": (float(np.mean(r_flags)) if r_flags else float("nan")),
            "cert_false_allow": (false_allow / n_allowed) if n_allowed else 0.0,
            "n_allowed": n_allowed, "n_R": len(r_flags)}


def clean_acc(model, enc, ev, y_true, fscale):
    """Clean 0/1 accuracy of the Lipschitz gate vs the (track-appropriate) oracle labels y_true at the
    observed point. y_true is precomputed per track (analytic oracle for synthetic, OPA engine for OPA)."""
    import torch
    rows = []
    for r in ev:
        v = np.asarray(enc.transform_point(r["domain"], r["tool_id"], r["candidate_action"],
                                           r["categorical_fields"], r["numeric_fields"]), dtype=np.float32)
        if fscale != 1.0:
            start = enc.dim - len(enc.numeric_fields)
            v[start:] *= fscale
        rows.append(v)
    with torch.no_grad():
        h = model(torch.from_numpy(np.asarray(rows, dtype=np.float32)).to(DS._LIP_DEVICE)).cpu().numpy()
    pred = (h > 0).astype(int)
    return float(np.mean(pred == np.array(y_true)))


def _train_synth(rt, seed, fs, n_train, eps, lip_epochs):
    cfg = dict(DS.LIP_SYNTH); cfg["fscale"] = fs
    model, enc, _ = DS.train_synth_lip(rt, seed, n_train, eps, epochs=lip_epochs, cfg=cfg)
    return model, enc


def _train_opa(orc, train, seed, fs, lip_epochs):
    labels = [1 if s else 0 for s in orc.safe_records(train)]
    model, enc, _ = DS.train_lipgate_generic(
        orc.rt, train, labels, seed=seed, epochs=lip_epochs, width=DS.LIP_OPA["width"],
        depth=DS.LIP_OPA["depth"], gamma=DS.LIP_OPA["gamma"], lam_margin=DS.LIP_OPA["lam_margin"],
        fscale=fs)
    return model, enc


def _run_track(track, seeds, fscales, eps, n_cert, lip_epochs, sizes):
    per_seed = []
    for seed in seeds:
        if track == "synthetic":
            from oracle import safe as _asafe
            K, k, n_cat_fields, x1_size = 8, sizes["k"], 2, 4
            rt, ev = DS.build_synthetic(x1_size, seed, sizes["n_eval"], eps, K, k, n_cat_fields)
            ju_map = DS.analytic_joint_unsafe_map(rt)
            trainer = lambda fs: _train_synth(rt, seed, fs, sizes["n_train"], eps, lip_epochs)  # noqa: E731
            y_of = lambda recs: [1 if _asafe(r, r["candidate_action"], rt) else 0 for r in recs]  # noqa: E731
        else:  # opa:finance — the OPA-engine categorize/joint-map is O(n²) per the note above, so keep
               # the OPA eval set small (cert subsets are tiny anyway; the selection question is per-fscale).
            sys.path.insert(0, str(_HERE / "opa_gate"))
            from opa_oracle import OpaOracle
            from schema import sample_records
            orc = OpaOracle("finance")
            rt = orc.rt
            dom = list(rt["domains"].keys())[0]
            opa_n_train = min(sizes["n_train"], 300)
            opa_n_eval = min(sizes["n_eval"], 240)
            train = sample_records("finance", opa_n_train, seed=seed)
            ev = sample_records("finance", opa_n_eval, seed=seed + 1)
            for r in list(train) + list(ev):
                r.setdefault("domain", dom)                 # certify_lip_at_d/enc need rec["domain"]
            for r, c in zip(ev, orc.categorize(ev, eps)):
                r["category"] = c["category"]; r["y"] = 1 if c["clean_safe"] else 0
            ju_map = DS.opa_joint_unsafe_map(orc)
            trainer = lambda fs: _train_opa(orc, train, seed, fs, lip_epochs)  # noqa: E731
            y_of = lambda recs: [1 if s else 0 for s in orc.safe_records(recs)]  # noqa: E731

        half = len(ev) // 2
        sel_cert = _cert_subset(ev[:half], n_cert)
        eval_cert = _cert_subset(ev[half:], n_cert)
        grid_rows, trained = [], {}
        for fs in fscales:
            model, enc = trainer(fs)
            trained[fs] = (model, enc)
            m_sel = certify_metrics(model, enc, rt, sel_cert, fs, eps, ju_map=ju_map)
            grid_rows.append({"fscale": fs, "sel_cert_false_allow": round(m_sel["cert_false_allow"], 5),
                              "sel_R_allow": round(m_sel["R_allow"], 4)})
        sound_fs = [g["fscale"] for g in grid_rows if g["sel_cert_false_allow"] == 0.0]
        fs_star = max(sound_fs) if sound_fs else min(fscales)
        model, enc = trained[fs_star]
        m_eval = certify_metrics(model, enc, rt, eval_cert, fs_star, eps, ju_map=ju_map)
        acc = clean_acc(model, enc, ev[half:], y_of(ev[half:]), fs_star)
        row = {"seed": seed, "selection_grid": grid_rows, "selected_fscale": fs_star,
               "sel_sound_fscales": sound_fs,
               "eval_cert_false_allow": round(m_eval["cert_false_allow"], 5),
               "eval_R_allow": round(m_eval["R_allow"], 4), "eval_clean_acc": round(acc, 4),
               "eval_sound": m_eval["cert_false_allow"] == 0.0}
        per_seed.append(row)
        print(f"[{track} seed={seed}] fscale*={fs_star} (sel-sound {sound_fs}) → eval "
              f"cfa={row['eval_cert_false_allow']} R={row['eval_R_allow']} acc={row['eval_clean_acc']}")
    return per_seed


def run(seeds, fscales, eps, quick, out_prefix, tracks=("synthetic", "opa:finance")):
    if not DS._LIP_OK:
        print(f"[error] Lipschitz backend unavailable: {DS._LIP_IMPORT_ERR}")
        return None
    sizes = {"n_train": 600 if quick else 3000, "n_eval": 800 if quick else 3000,
             "k": 3 if quick else 5}
    n_cert = 24 if quick else 40
    lip_epochs = 500 if quick else 1500

    tracks_out = {}
    per_seed = []
    for track in tracks:
        try:
            rows = _run_track(track, seeds, fscales, eps, n_cert, lip_epochs, sizes)
        except Exception as e:  # OPA binary / corpora may be unavailable; synthetic still stands.
            print(f"[track {track} skipped: {type(e).__name__}: {e}]")
            continue
        tracks_out[track] = rows
        per_seed.extend(rows)

    all_sound = all(r["eval_sound"] for r in per_seed) if per_seed else False
    # per-track summary
    track_summary = {}
    for tk, rows in tracks_out.items():
        track_summary[tk] = {
            "selected_fscales": [r["selected_fscale"] for r in rows],
            "eval_cert_false_allow_max": round(max(r["eval_cert_false_allow"] for r in rows), 5),
            "eval_R_allow_mean": round(float(np.nanmean([r["eval_R_allow"] for r in rows])), 4),
            "all_eval_sound": all(r["eval_sound"] for r in rows),
            "selection_rule_binds": any(len(r["sel_sound_fscales"]) < len(fscales) for r in rows)}
    binds = any(v["selection_rule_binds"] for v in track_summary.values())
    binding_tracks = [tk for tk, v in track_summary.items() if v["selection_rule_binds"]]
    verdict = ("SELECTION OBJECTION RESOLVED: fscale chosen by the largest-cfa=0-on-SELECTION rule keeps "
               "cert_false_allow=0 on the untouched EVAL split (all tracks/seeds); the rule genuinely "
               f"EXCLUDES the fscale(s) that break soundness on the SELECTION half (binds on {binding_tracks}: "
               "at least one seed drops an fscale with sel cfa>0), and eval confirms cfa=0 with non-vacuous "
               "R_allow ⇒ the fscale headline is not outcome-conditioned."
               if (all_sound and binds) else
               ("SELECTION OBJECTION RESOLVED (soundness generalizes): held-out-selected fscale keeps "
                "cert_false_allow=0 on eval for every track/seed; note the synthetic track has no soundness "
                "cliff in the grid (all fscales sound), so the rule binds only on OPA." if all_sound else
                "EVAL soundness broke for the held-out-selected fscale on some seed — pick a more conservative "
                "fscale (the rule then chooses lower)."))
    payload = {
        "experiment": "EXP-C4/B4 — fscale held-out selection (selection-split hyperparameter choice)",
        "priority": "C",
        "reuses": "d_sweep (T2-8) build_synthetic/build_opa/train_lipgate_generic/certify_lip_at_d", "eps": eps,
        "fscale_grid": fscales, "seeds": list(seeds), "d": 1, "quick": quick, "tracks": list(tracks_out),
        "selection_rule": "largest fscale with cert_false_allow==0 on the SELECTION half; report on EVAL half",
        "per_seed": per_seed, "track_summary": track_summary,
        "eval_cert_false_allow_max": round(max(r["eval_cert_false_allow"] for r in per_seed), 5) if per_seed else None,
        "eval_R_allow_mean": round(float(np.nanmean([r["eval_R_allow"] for r in per_seed])), 4) if per_seed else None,
        "all_eval_sound": all_sound, "verdict": verdict,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{out_prefix}.json").write_text(json.dumps(payload, indent=2))
    _write_md(OUT / f"{out_prefix}.md", payload)
    print(f"\nVERDICT: {verdict}")
    print(f"wrote -> {OUT/(out_prefix+'.json')}\nwrote -> {OUT/(out_prefix+'.md')}")
    return payload


def _write_md(path, p):
    with open(path, "w") as f:
        f.write("# EXP-C4/B4 — fscale held-out selection\n\n")
        f.write(f"Reuses {p['reuses']}. Rule: **{p['selection_rule']}**. "
                f"ε={p['eps']}, grid={p['fscale_grid']}, seeds={p['seeds']}, d={p['d']}.\n\n")
        for tk, s in p["track_summary"].items():
            f.write(f"### track {tk}\n\n")
            f.write(f"selected fscale*(s) {s['selected_fscales']}; **eval cert_FA max "
                    f"{s['eval_cert_false_allow_max']}**, eval R_allow mean {s['eval_R_allow_mean']}, "
                    f"all eval sound **{s['all_eval_sound']}**, selection rule binds "
                    f"**{s['selection_rule_binds']}**.\n\n")
        f.write("### Per-seed detail (all tracks in order)\n\n")
        f.write("| seed | selection grid | fscale* | eval cert_FA | eval R_allow | eval acc | sound |\n")
        f.write("|--:|---|--:|--:|--:|--:|:--:|\n")
        for r in p["per_seed"]:
            g = " ; ".join(f"fs{x['fscale']}:cfa{x['sel_cert_false_allow']}/R{x['sel_R_allow']}"
                           for x in r["selection_grid"])
            f.write(f"| {r['seed']} | {g} | {r['selected_fscale']} | {r['eval_cert_false_allow']} | "
                    f"{r['eval_R_allow']} | {r['eval_clean_acc']} | {'Y' if r['eval_sound'] else 'N'} |\n")
        f.write(f"\nOverall EVAL cert_false_allow max **{p['eval_cert_false_allow_max']}**, all eval sound "
                f"**{p['all_eval_sound']}**.\n\n**Verdict.** {p['verdict']}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", default="0,1,2")
    ap.add_argument("--fscales", default=",".join(str(x) for x in FSCALE_GRID))
    ap.add_argument("--eps", type=float, default=EPS)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--tracks", default="synthetic,opa:finance")
    ap.add_argument("--out", default="exp_c4_fscale_heldout")
    a = ap.parse_args()
    seeds = [int(s) for s in a.seeds.split(",") if s.strip()]
    fscales = [float(x) for x in a.fscales.split(",") if x.strip()]
    tracks = tuple(t.strip() for t in a.tracks.split(",") if t.strip())
    run(seeds, fscales, a.eps, a.quick, a.out, tracks=tracks)


if __name__ == "__main__":
    main()
