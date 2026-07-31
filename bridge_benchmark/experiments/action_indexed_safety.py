#!/usr/bin/env python3
"""
action_indexed_safety.py — NEW_EXPS_6 Part G. The certified object is Safe(z, a), NOT Safe(z): the same
typed return can be safe for one action and unsafe for another, so the gate is action-indexed and is
*not* a generic anomaly detector over z.

For each fixed typed return z we evaluate several candidate actions. In the realistic schemas only the
PRIVILEGED action (approve_transaction / suppress_alert / allow_login) carries a policy rule; the other
actions (reject / escalate / notify / require_mfa / page / …) are conservative, non-consequential
fallbacks that are always policy-safe to take. Hence the SAME z that is unsafe for the privileged action
is safe for escalation/notification — Safe(z, a) genuinely depends on a.

Metrics per domain:
    action_dependence_rate              fraction of z with ∃ a1,a2: Safe(z,a1) != Safe(z,a2)
    same_z_different_action_rate        alias of the above (named per the task)
    gate_decision_variation_over_actions mean over z of (#distinct decisions over actions − 1)/(#actions − 1)
    privileged_unsafe_rate              fraction of z where the privileged action is unsafe

Writes bridge_benchmark/cert/out/action_indexed_safety.{csv,md}.
"""
from __future__ import annotations

import argparse
import csv
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
_root = Path(__file__).resolve().parents[1]
for p in ("generators", "experiments"):
    sys.path.insert(0, str(_root / p))

from oracle import safe, get_rule, _x1  # noqa: E402
from realistic_schemas import finance_schema, monitoring_schema, ops_security_schema  # noqa: E402
from synthetic_tools import sample_records, DOMAIN  # noqa: E402

OUT = _root / "cert" / "out"
SCHEMAS = {"finance_compliance": finance_schema, "sre_monitoring": monitoring_schema,
           "ops_security": ops_security_schema}
# privileged (ruled) action + conservative fallback actions (no rule -> always policy-safe to take)
ACTIONS = {
    "finance_compliance": ["approve_transaction", "reject_transaction", "escalate_to_human", "notify_user"],
    "sre_monitoring": ["suppress_alert", "page_oncall", "restart_service", "escalate_to_human"],
    "ops_security": ["allow_login", "deny_login", "require_mfa", "escalate_to_human"],
}
COLS = ["domain", "n", "n_actions", "action_dependence_rate", "same_z_different_action_rate",
        "gate_decision_variation_over_actions", "privileged_unsafe_rate"]


def _safe_for_action(rec, a, rt):
    """Safe(z, a): if a carries a policy rule (the privileged action), use the analytic oracle; else a
    is a conservative fallback (escalate/notify/reject/require_mfa/…) that is always policy-safe."""
    dc = rt["domains"][DOMAIN]
    if get_rule(dc, rec["tool_id"], a, _x1(rec)) is None:
        return True
    return bool(safe({**rec, "candidate_action": a}, a, rt))


def run_domain(domain, n, eps, seed):
    _, rt = SCHEMAS[domain]()
    recs = sample_records(rt, n, eps=eps, seed=seed)
    actions = ACTIONS[domain]
    priv = actions[0]
    n_dep = n_priv_unsafe = 0
    var_acc = 0.0
    for r in recs:
        decisions = [_safe_for_action(r, a, rt) for a in actions]
        distinct = len(set(decisions))
        if distinct > 1:
            n_dep += 1
        var_acc += (distinct - 1) / (len(actions) - 1)
        if not _safe_for_action(r, priv, rt):
            n_priv_unsafe += 1
    nn = len(recs)
    return {"domain": domain, "n": nn, "n_actions": len(actions),
            "action_dependence_rate": round(n_dep / nn, 4),
            "same_z_different_action_rate": round(n_dep / nn, 4),
            "gate_decision_variation_over_actions": round(var_acc / nn, 4),
            "privileged_unsafe_rate": round(n_priv_unsafe / nn, 4)}


def run(domains=None, n=20000, eps=0.10, seed=0, out_csv=None, out_md=None):
    domains = domains or list(SCHEMAS)
    out_csv = Path(out_csv) if out_csv else OUT / "action_indexed_safety.csv"
    out_md = Path(out_md) if out_md else OUT / "action_indexed_safety.md"
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    rows = [run_domain(d, n, eps, seed) for d in domains]
    for r in rows:
        print(f"{r['domain']:18s} action_dependence={r['action_dependence_rate']:.3f} "
              f"priv_unsafe={r['privileged_unsafe_rate']:.3f} "
              f"variation={r['gate_decision_variation_over_actions']:.3f}")
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS); w.writeheader(); w.writerows(rows)
    md = ["# Action-indexed safety — the certified object is Safe(z, a), not Safe(z)\n",
          "For a fixed typed return z we evaluate several candidate actions. The privileged action "
          "carries a policy rule; escalation/notification/etc. are conservative fallbacks that are "
          "always policy-safe. `action_dependence_rate` = fraction of z where the actions disagree on "
          f"safety. n={n}/domain, eps={eps}, seed={seed}.\n",
          "| " + " | ".join(COLS) + " |", "| " + " | ".join("---" for _ in COLS) + " |"]
    for r in rows:
        md.append("| " + " | ".join(str(r[c]) for c in COLS) + " |")
    md.append("\n**Reading.** The same returned object can be safe for escalation or notification but "
              "unsafe for approval, deletion, or suppression. Therefore the certified object must be "
              "Allow(z, a), not Allow(z): the gate is action-indexed, not a generic anomaly detector "
              "over z.\n")
    out_md.write_text("\n".join(md) + "\n")
    print(f"\nwrote -> {out_csv}\nwrote -> {out_md}")
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--domains", default=",".join(SCHEMAS))
    ap.add_argument("--n", type=int, default=20000)
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out-csv", default=None)
    ap.add_argument("--out-md", default=None)
    args = ap.parse_args()
    domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    run(domains=domains, n=args.n, eps=args.eps, seed=args.seed, out_csv=args.out_csv, out_md=args.out_md)


if __name__ == "__main__":
    main()
