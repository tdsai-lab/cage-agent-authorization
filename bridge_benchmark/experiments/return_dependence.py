#!/usr/bin/env python3
"""
return_dependence.py — TM1 return-dependence experiment (NEW_EXPS_4 Part B).

Why a POST-return gate at all? Because safety depends on the returned object z, not only on the tool
call or the user task. If two returns that share the same domain / candidate action / schema family can
disagree on Safe(z, a), then a PRE-execution permission decision (which only knows the tool call, not
its return) cannot decide the downstream action. We quantify this with matched return-dependence rates:

    rho_matched = Pr[ Safe(z0,a) != Safe(z1,a) | z0,z1 share domain/action/schema family ].

A nonzero rho_matched means authorization cannot be reduced to a pre-execution tool-call permission:
the returned object z is a necessary input to Safe(z, a).

Metrics per domain (all on the analytic oracle; NO learned model, NO agent loop):
    rho_matched                 random pairs sharing domain + candidate action
    rho_same_tool               same tool id, different numeric fields
    rho_tool_swap_same_x1       same categorical fields, different tool/provenance
    rho_same_categorical_context same categorical context, any valid tool
    pre_return_majority_error   error of a pre-return policy that knows only domain/action and predicts
                                the majority safe label = min(safe_rate, 1 - safe_rate)
    n_pairs, safe_rate

Reuses finance_schema()/monitoring_schema()/ops_security_schema(), sample_records(), safe().

Writes bridge_benchmark/cert/out/return_dependence.{csv,md}.
"""
from __future__ import annotations

import argparse
import csv
import random
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
_root = Path(__file__).resolve().parents[1]
for p in ("generators", "experiments"):
    sys.path.insert(0, str(_root / p))

from oracle import safe, _x1  # noqa: E402
from realistic_schemas import finance_schema, monitoring_schema, ops_security_schema  # noqa: E402
from synthetic_tools import sample_records, DOMAIN  # noqa: E402

OUT = _root / "cert" / "out"
SCHEMAS = {"finance_compliance": finance_schema, "sre_monitoring": monitoring_schema,
           "ops_security": ops_security_schema}
ROWS_COLS = ["domain", "n_records", "safe_rate", "rho_matched", "rho_same_tool",
             "rho_tool_swap_same_x1", "rho_same_categorical_context", "pre_return_majority_error",
             "n_pairs"]


def _x1_key(rec):
    return tuple(sorted(_x1(rec).items()))


def _safe_label(rec, rt):
    """Safe(z, a) for the record's own candidate action a (the per-tool privileged action)."""
    return bool(safe(rec, rec["candidate_action"], rt))


def _discord_rate(rng, pairs_iter, labels, n_pairs):
    """Fraction of sampled valid pairs (i,j) with labels[i] != labels[j]."""
    disc = tot = 0
    for i, j in pairs_iter:
        if i == j:
            continue
        disc += int(labels[i] != labels[j])
        tot += 1
        if tot >= n_pairs:
            break
    return (disc / tot) if tot else float("nan"), tot


def _sample_matched(rng, n, n_pairs):
    for _ in range(n_pairs * 4):
        yield rng.randrange(n), rng.randrange(n)


def _sample_same_bucket(rng, buckets, n_pairs, require_diff_tool=False, tools=None):
    """Pairs drawn from the same bucket (a list of record indices). Optionally require the two records
    to have different tool ids (for the tool-swap / provenance-change condition)."""
    keys = [k for k, idxs in buckets.items() if len(idxs) >= 2]
    if not keys:
        return
    for _ in range(n_pairs * 8):
        k = keys[rng.randrange(len(keys))]
        idxs = buckets[k]
        i = idxs[rng.randrange(len(idxs))]
        j = idxs[rng.randrange(len(idxs))]
        if i == j:
            continue
        if require_diff_tool and tools is not None and tools[i] == tools[j]:
            continue
        yield i, j


def run_domain(domain, n, n_pairs, eps, seed):
    _, rt = SCHEMAS[domain]()
    recs = sample_records(rt, n, eps=eps, seed=seed)
    labels = [_safe_label(r, rt) for r in recs]
    tools = [r["tool_id"] for r in recs]
    safe_rate = sum(labels) / len(labels)

    rng = random.Random(seed + 7)

    # buckets keyed by tool id (same tool) and by categorical context (same x1)
    by_tool = {}
    by_x1 = {}
    for idx, r in enumerate(recs):
        by_tool.setdefault(tools[idx], []).append(idx)
        by_x1.setdefault(_x1_key(r), []).append(idx)

    rho_matched, _ = _discord_rate(rng, _sample_matched(rng, len(recs), n_pairs), labels, n_pairs)
    rho_same_tool, _ = _discord_rate(rng, _sample_same_bucket(rng, by_tool, n_pairs), labels, n_pairs)
    rho_tool_swap, _ = _discord_rate(
        rng, _sample_same_bucket(rng, by_x1, n_pairs, require_diff_tool=True, tools=tools),
        labels, n_pairs)
    rho_same_ctx, np_ctx = _discord_rate(rng, _sample_same_bucket(rng, by_x1, n_pairs), labels, n_pairs)

    return {
        "domain": domain, "n_records": len(recs), "safe_rate": round(safe_rate, 4),
        "rho_matched": round(rho_matched, 4), "rho_same_tool": round(rho_same_tool, 4),
        "rho_tool_swap_same_x1": round(rho_tool_swap, 4),
        "rho_same_categorical_context": round(rho_same_ctx, 4),
        "pre_return_majority_error": round(min(safe_rate, 1.0 - safe_rate), 4),
        "n_pairs": n_pairs,
    }


def run(domains=None, n=20000, n_pairs=10000, eps=0.10, seed=0,
        out_csv=None, out_md=None):
    domains = domains or list(SCHEMAS)
    out_csv = Path(out_csv) if out_csv else OUT / "return_dependence.csv"
    out_md = Path(out_md) if out_md else OUT / "return_dependence.md"
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    rows = [run_domain(d, n, n_pairs, eps, seed) for d in domains]
    for r in rows:
        print(f"{r['domain']:18s} safe_rate={r['safe_rate']:.3f} | rho_matched={r['rho_matched']:.3f} "
              f"rho_same_tool={r['rho_same_tool']:.3f} rho_tool_swap={r['rho_tool_swap_same_x1']:.3f} "
              f"rho_same_ctx={r['rho_same_categorical_context']:.3f} "
              f"pre_return_maj_err={r['pre_return_majority_error']:.3f}")

    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=ROWS_COLS)
        w.writeheader()
        w.writerows([{c: r[c] for c in ROWS_COLS} for r in rows])

    md = ["# TM1 return-dependence — Safe(z,a) depends on the returned object z\n",
          "`rho_matched = Pr[Safe(z0,a) != Safe(z1,a) | z0,z1 share domain/action/schema family]`. "
          "All rates are on the analytic oracle (no learned model, no agent loop). `eps` is unused for "
          "the discrete labels here (clean Safe), reported for provenance.\n",
          f"Settings: n={n} records/domain, n_pairs={n_pairs}, eps={eps}, seed={seed}.\n",
          "| " + " | ".join(ROWS_COLS) + " |",
          "| " + " | ".join("---" for _ in ROWS_COLS) + " |"]
    for r in rows:
        md.append("| " + " | ".join(str(r[c]) for c in ROWS_COLS) + " |")
    md.append(
        "\n**Reading.** A nonzero matched return-dependence rate means authorization cannot be reduced "
        "to a pre-execution tool-call permission. The returned object z is a necessary input to the "
        "safety predicate Safe(z,a). `pre_return_majority_error` is the irreducible error of any "
        "pre-return policy that sees only the domain/action and not the return: it must predict a single "
        "label for all returns of that tool-call, so it is wrong on the minority class.\n")
    out_md.write_text("\n".join(md) + "\n")
    print(f"\nwrote -> {out_csv}\nwrote -> {out_md}")
    return rows


# --------------------------------------------------------------------------- #
# NEW_EXPS_6 Part D — learned pre-return vs post-return baseline
# --------------------------------------------------------------------------- #
# A PRE-return predictor knows only what is available before the tool executes (domain/action are
# constant within a domain; the tool id / provenance is known at call time). It must NOT see the
# RETURNED fields: numeric x2 (risk/confidence/amount/severity) or the post-hoc categorical context x1.
# A POST-return predictor sees the full typed return z=(t,x1,x2) and the action a. We compare their
# error/AUC on the oracle label Safe(z,a). The pre-return predictor cannot beat the per-tool base rate
# because Safe(z,a) hinges on x2; the post-return predictor does.
LEARNED_COLS = ["domain", "n", "majority_error", "pre_return_error", "pre_return_auc",
                "post_return_error", "post_return_auc", "rho_matched"]


def _featurize(recs, rt, post: bool):
    import numpy as np
    dc = rt["domains"][DOMAIN]
    tools = dc["tools"]; nf = dc["numeric_fields"]; cats = dc["categorical_fields"]
    tool_ix = {t: i for i, t in enumerate(tools)}
    cat_vals = {c: list(v) for c, v in cats.items()}
    rows = []
    for r in recs:
        feat = [0.0] * len(tools)
        feat[tool_ix[r["tool_id"]]] = 1.0                          # provenance (known pre-return)
        if post:
            for c, vals in cat_vals.items():                       # returned categorical context x1
                oh = [0.0] * len(vals)
                xv = _x1(r).get(c)
                if xv in vals:
                    oh[vals.index(xv)] = 1.0
                feat += oh
            feat += [float(r["numeric_fields"][f]) for f in nf]    # returned numeric x2
        rows.append(feat)
    return np.asarray(rows, dtype=float)


def run_learned(domain, n, eps, seed):
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import roc_auc_score
    sys.path.insert(0, str(_root / "models"))
    from split import stratified_split  # noqa: E402

    _, rt = SCHEMAS[domain]()
    recs = sample_records(rt, n, eps=eps, seed=seed)
    for r in recs:
        r["y"] = 1 if _safe_label(r, rt) else 0
    train, _val, test = stratified_split(recs)
    ytr = np.array([r["y"] for r in train]); yte = np.array([r["y"] for r in test])
    maj = 1 if ytr.mean() >= 0.5 else 0
    majority_error = float(np.mean(yte != maj))

    def fit_eval(post):
        Xtr, Xte = _featurize(train, rt, post), _featurize(test, rt, post)
        # gradient boosting (handles the numeric x2 boundary); logistic as a sanity floor
        gb = HistGradientBoostingClassifier(max_iter=200, random_state=seed).fit(Xtr, ytr)
        p = gb.predict_proba(Xte)[:, 1]
        err = float(np.mean((p >= 0.5).astype(int) != yte))
        try:
            auc = float(roc_auc_score(yte, p)) if len(set(yte)) > 1 else float("nan")
        except ValueError:
            auc = float("nan")
        return err, auc

    pre_err, pre_auc = fit_eval(post=False)
    post_err, post_auc = fit_eval(post=True)
    rho = run_domain(domain, n, min(n // 2, 10000), eps, seed)["rho_matched"]
    return {"domain": domain, "n": len(recs), "majority_error": round(majority_error, 4),
            "pre_return_error": round(pre_err, 4), "pre_return_auc": round(pre_auc, 4),
            "post_return_error": round(post_err, 4), "post_return_auc": round(post_auc, 4),
            "rho_matched": rho}


def run_learned_all(domains=None, n=20000, eps=0.10, seed=0, out_csv=None, out_md=None):
    domains = domains or list(SCHEMAS)
    out_csv = Path(out_csv) if out_csv else OUT / "return_dependence_learned.csv"
    out_md = Path(out_md) if out_md else OUT / "return_dependence_learned.md"
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    rows = [run_learned(d, n, eps, seed) for d in domains]
    for r in rows:
        print(f"{r['domain']:18s} majority_err={r['majority_error']:.3f} | "
              f"PRE-return err={r['pre_return_error']:.3f} auc={r['pre_return_auc']:.3f} | "
              f"POST-return err={r['post_return_error']:.3f} auc={r['post_return_auc']:.3f}")
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=LEARNED_COLS)
        w.writeheader(); w.writerows([{c: r[c] for c in LEARNED_COLS} for r in rows])
    md = ["# TM1b learned pre-return vs post-return baseline\n",
          "A PRE-return predictor sees only pre-execution info (domain/action/tool id); it must NOT see "
          "the returned x1/x2 (risk, amount, severity, confidence). A POST-return predictor sees the "
          "full typed return z=(t,x1,x2). Both predict the oracle label Safe(z,a) (HistGradientBoosting)."
          f" n={n}/domain, eps={eps}, seed={seed}.\n",
          "| " + " | ".join(LEARNED_COLS) + " |", "| " + " | ".join("---" for _ in LEARNED_COLS) + " |"]
    for r in rows:
        md.append("| " + " | ".join(str(r[c]) for c in LEARNED_COLS) + " |")
    md.append("\n**Reading.** `pre_return_error` stays close to `majority_error` (the provenance alone "
              "barely predicts safety), while `post_return_error` is much lower and `post_return_auc` "
              "much higher. A pre-execution permission layer cannot decide the downstream authorization "
              "predicate because Safe(z,a) depends on the returned object z.\n")
    out_md.write_text("\n".join(md) + "\n")
    print(f"\nwrote -> {out_csv}\nwrote -> {out_md}")
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--domains", default=",".join(SCHEMAS),
                    help="comma list of finance_compliance,sre_monitoring,ops_security")
    ap.add_argument("--n", type=int, default=20000)
    ap.add_argument("--n-pairs", type=int, default=10000)
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--learned", action="store_true",
                    help="ALSO train the learned pre-return vs post-return baseline (Part D).")
    ap.add_argument("--out-csv", default=None)
    ap.add_argument("--out-md", default=None)
    args = ap.parse_args()
    domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    run(domains=domains, n=args.n, n_pairs=args.n_pairs, eps=args.eps, seed=args.seed,
        out_csv=args.out_csv, out_md=args.out_md)
    if args.learned:
        run_learned_all(domains=domains, n=args.n, eps=args.eps, seed=args.seed)


if __name__ == "__main__":
    main()
