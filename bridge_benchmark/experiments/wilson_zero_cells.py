#!/usr/bin/env python3
"""M1 — Wilson upper bounds + explicit n/N for every zero cell.

Motivation: "Zero cells lack denominators and confidence intervals. Different denominators
(W, certified allows, robust-safe records, category counts) are easy to conflate;
only S35 carries a Wilson bound."

This is pure post-processing (no GPU, no LLM, no re-training). For every zero cell
the paper quotes across Tables 4/5/6 (+ S5/S8/S14/S20/S22) it emits:
    numerator k   /   denominator N   /   observed rate   /   Wilson-95% upper
plus an exact Clopper-Pearson upper as a cross-check, AND — the whole point of C4 —
an explicit `denominator_semantics` string per row so the denominators cannot be
conflated.

Denominator conventions (the four the reviewers said get conflated):
  * cert_false_allow : k = oracle-UNSAFE among gate-ALLOWED ; N = # gate-ALLOWED.
  * C_allow          : k = Category-C records the gate ALLOWED ; N = # Category-C records.
  * U_allow          : k = Category-U records the gate ALLOWED ; N = # Category-U records.
  * unsafe_execution : k = unsafe executions ; N = # episodes (agent / e2e).
  * attack_false_allow: k = in-budget exploit successes ; N = # exploit witnesses (W).

Sources: where a per-example JSONL exists we COUNT (exact k, exact N). Where only a
summary with recorded category rates + N exists, we derive the per-cell N from those
rates (k is a reported 0). Every row is tagged with `source` and `evidence`
(`per_example` vs `summary_recorded_N`) so provenance is auditable.

Outputs (gitignored cert/out):
    cert/out/wilson_zero_cells.csv
    cert/out/wilson_zero_cells.md
"""
from __future__ import annotations

import csv
import json
import math
import os
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(os.path.join(HERE, "..", "cert", "out"))
REG = os.path.join(HERE, "policy_idiom_prevalence", "results", "tables")

Z95 = 1.959963984540054  # two-sided 95% normal quantile


# --------------------------------------------------------------------------- #
# statistics                                                                  #
# --------------------------------------------------------------------------- #
def wilson_upper(k: int, n: int, z: float = Z95) -> float:
    """Upper end of the two-sided 95% Wilson score interval for k/n. Pure stdlib."""
    if n <= 0:
        return float("nan")
    p = k / n
    denom = 1.0 + z * z / n
    center = p + z * z / (2 * n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return min(1.0, (center + half) / denom)


def cp_upper(k: int, n: int, conf: float = 0.95) -> float:
    """Exact Clopper-Pearson two-sided upper bound (cross-check for Wilson).

    Uses the Beta quantile; scipy if present, otherwise a stdlib bisection on the
    regularized incomplete Beta (via math.lgamma continued-fraction is overkill —
    for k=0 the upper is closed-form 1-(alpha/2)**(1/n), which covers every zero
    cell here; the general path falls back to scipy only when k>0)."""
    if n <= 0:
        return float("nan")
    alpha = 1.0 - conf
    if k == 0:
        return 1.0 - (alpha / 2.0) ** (1.0 / n)
    try:
        from scipy.stats import beta  # type: ignore
        return float(beta.ppf(1 - alpha / 2.0, k + 1, n - k))
    except Exception:
        return float("nan")


def row(table, setting, cell, metric, k, n, denom_semantics, source, evidence):
    return {
        "table": table,
        "setting": setting,
        "cell": cell,
        "metric": metric,
        "k": int(k),
        "N": int(n),
        "rate": round(k / n, 6) if n else float("nan"),
        "wilson95_upper": round(wilson_upper(k, n), 6),
        "cp95_upper": round(cp_upper(k, n), 6),
        "denominator_semantics": denom_semantics,
        "source": source,
        "evidence": evidence,
    }


def _load_jsonl(path):
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _load_csv(path):
    with open(path) as fh:
        return list(csv.DictReader(fh))


# --------------------------------------------------------------------------- #
# per-example sources (exact k, exact N)                                       #
# --------------------------------------------------------------------------- #
def rows_certificates(rows):
    """Synthetic canonical certificate set (Tables 4/5 synthetic rows)."""
    path = os.path.join(OUT, "certificates.jsonl")
    if not os.path.exists(path):
        return
    recs = _load_jsonl(path)
    # `allow` is the certified-gate decision; `cert_allow` is a diagnostic sub-record.
    allowed = [r for r in recs if r.get("allow")]
    fa = [r for r in allowed if r.get("safety_label") == "unsafe"]
    rows.append(row("T4/T5-syn", "synthetic canonical (enumerate+RS gate)",
                    "certified-allow decisions", "cert_false_allow",
                    len(fa), len(allowed),
                    "N = certified-allow decisions; k = oracle-unsafe among them",
                    "certificates.jsonl", "per_example"))
    for cat in ("C", "U"):
        grp = [r for r in recs if r.get("category") == cat]
        k = sum(1 for r in grp if r.get("allow"))
        rows.append(row("T4/T5-syn", "synthetic canonical (enumerate+RS gate)",
                        f"Category-{cat} records", f"{cat}_allow", k, len(grp),
                        f"N = Category-{cat} records; k = of them the gate allowed",
                        "certificates.jsonl", "per_example"))


def rows_grouped_exec(rows, fname, table, gates, attacks, label):
    """e2e #29 and agent-loop: unsafe_execution over episodes, exact."""
    path = os.path.join(OUT, fname)
    if not os.path.exists(path):
        return
    recs = _load_jsonl(path)
    agg = defaultdict(lambda: [0, 0])  # (domain,gate,attack) -> [k, N]
    for r in recs:
        g, a = r.get("gate"), r.get("attack")
        if g not in gates or a not in attacks:
            continue
        key = (r.get("domain"), g, a)
        agg[key][1] += 1
        if r.get("unsafe_execution"):
            agg[key][0] += 1
    for (dom, g, a), (k, n) in sorted(agg.items()):
        if k != 0:      # M1 audits the ZERO cells; non-zero cells already carry a rate
            continue
        rows.append(row(table, f"{label}: {dom} / {g} / attack={a}",
                        "episodes", "unsafe_execution", k, n,
                        "N = episodes; k = unsafe (privileged) executions committed",
                        fname, "per_example"))


# --------------------------------------------------------------------------- #
# summary sources (recorded category rates -> per-cell N; k is reported 0)     #
# --------------------------------------------------------------------------- #
def rows_reg(rows):
    """REG PSD2/AML — exact category counts from the tracked prevalence CSV."""
    prev_p = os.path.join(REG, "regulatory_c_prevalence.csv")
    gate_p = os.path.join(REG, "regulatory_certified_gate.csv")
    if not (os.path.exists(prev_p) and os.path.exists(gate_p)):
        return
    prev = _load_csv(prev_p)
    gate = _load_csv(gate_p)
    gidx = {(g["policy_family"], g["sampling_mode"], g["epsilon"]): g for g in gate}
    for p in prev:
        key = (p["policy_family"], p["sampling_mode"], p["epsilon"])
        g = gidx.get(key)
        if g is None:
            continue
        n = int(float(p["n"]))
        c_count = int(float(p["C_count"]))
        u_count = round(float(p["U_pct"]) * n)          # U_pct is a fraction here
        r_count = round(float(p["R_pct"]) * n)
        allowed = round(float(g["R_allow"]) * r_count)  # gate allows only within R
        tag = f"REG {p['policy_family']}/{p['sampling_mode']}/eps={p['epsilon']}"
        if float(g["C_allow"]) == 0.0 and c_count > 0:
            rows.append(row("T5-REG", tag, "Category-C records", "C_allow",
                            0, c_count, "N = Category-C records (engine-labeled)",
                            "regulatory_c_prevalence.csv + regulatory_certified_gate.csv",
                            "summary_recorded_N"))
        if float(g["U_allow"]) == 0.0 and u_count > 0:
            rows.append(row("T5-REG", tag, "Category-U records", "U_allow",
                            0, u_count, "N = Category-U records = round(U_pct*n)",
                            "regulatory_c_prevalence.csv + regulatory_certified_gate.csv",
                            "summary_recorded_N"))
        if float(g["cert_false_allow"]) == 0.0 and allowed > 0:
            rows.append(row("T5-REG", tag, "certified-allow decisions", "cert_false_allow",
                            0, allowed,
                            "N = certified-allow decisions = round(R_allow*R_count)",
                            "regulatory_c_prevalence.csv + regulatory_certified_gate.csv",
                            "summary_recorded_N"))


def rows_nab(rows):
    """T2-7 NAB (real EC2/RDS CPU) — per-seed counts summed over 3 seeds."""
    path = os.path.join(OUT, "exp_second_dataset", "summary.csv")
    if not os.path.exists(path):
        return
    recs = [r for r in _load_csv(path) if r.get("seed", "").strip().isdigit()]
    for backend in ("lip", "rs", "exact"):
        c_n = u_n = allow_n = 0
        ok = True
        for r in recs:
            n = int(float(r["n_balanced"]))
            c_n += round(float(r["C_pct"]) / 100 * n)
            u_n += round(float(r["U_pct"]) / 100 * n)
            r_n = round(float(r["R_pct"]) / 100 * n)
            allow_n += round(float(r[f"R_allow_{backend}"]) * r_n)
            for m in (f"cert_false_allow_{backend}", f"C_allow_{backend}", f"U_allow_{backend}"):
                v = r.get(m, "")
                if v not in ("", None) and float(v) != 0.0:
                    ok = False
        if not ok:
            continue
        tag = f"NAB (real EC2/RDS CPU) / backend={backend}"
        rows.append(row("T5/S14-NAB", tag, "Category-C records", "C_allow", 0, c_n,
                        "N = Category-C records over 3 seeds",
                        "exp_second_dataset/summary.csv", "summary_recorded_N"))
        rows.append(row("T5/S14-NAB", tag, "Category-U records", "U_allow", 0, u_n,
                        "N = Category-U records over 3 seeds",
                        "exp_second_dataset/summary.csv", "summary_recorded_N"))
        rows.append(row("T5/S14-NAB", tag, "certified-allow decisions", "cert_false_allow",
                        0, allow_n,
                        "N = certified-allow decisions over 3 seeds = sum round(R_allow*R_count)",
                        "exp_second_dataset/summary.csv", "summary_recorded_N"))


def rows_opa_full(rows):
    """OPA Track C policy-as-code sweep — canonical operating point per domain/backend."""
    path = os.path.join(OUT, "exp_opa_full", "summary.json")
    if not os.path.exists(path):
        return
    d = json.load(open(path))
    cfg = d["config"]
    n_per_cell = cfg["n_eval"] * len(cfg["seeds"])   # eval points aggregated over seeds
    for c in d["cells"]:
        if not (abs(c["eps"] - 0.1) < 1e-9 and abs(c["tau"] - 0.9) < 1e-9):
            continue  # canonical strict operating point only, keep table compact
        if not (c["C_allow_mean"] == 0 and c["U_allow_mean"] == 0 and c["cert_false_allow_mean"] == 0):
            continue
        c_n = round(c["C_rate_mean"] * n_per_cell)
        u_n = round(c["U_rate_mean"] * n_per_cell)
        allow_n = round(c["R_allow_mean"] * c["R_rate_mean"] * n_per_cell)
        tag = f"OPA-TrackC {c['domain']}/{c['backend']} (eps=0.1,tau=0.9)"
        rows.append(row("T4-OPA", tag, "Category-C records", "C_allow", 0, c_n,
                        "N = Category-C records (OPA-labeled) over 3 seeds",
                        "exp_opa_full/summary.json", "summary_recorded_N"))
        rows.append(row("T4-OPA", tag, "Category-U records", "U_allow", 0, u_n,
                        "N = Category-U records (OPA-labeled) over 3 seeds",
                        "exp_opa_full/summary.json", "summary_recorded_N"))
        rows.append(row("T4-OPA", tag, "certified-allow decisions", "cert_false_allow", 0, allow_n,
                        "N = certified-allow decisions over 3 seeds",
                        "exp_opa_full/summary.json", "summary_recorded_N"))


def rows_realistic(rows):
    """Realistic-schema synthetic scale study (Tables S) — n_records + category rates."""
    path = os.path.join(OUT, "realistic_schema_results.csv")
    if not os.path.exists(path):
        return
    for r in _load_csv(path):
        n = int(float(r["n_records"]))
        c_n = round(float(r["C_pct"]) / 100 * n)
        u_n = round(float(r["U_pct"]) / 100 * n)
        r_n = round(float(r["R_pct"]) / 100 * n)
        allow_n = round(float(r["R_allow"]) * r_n)
        tag = f"realistic-schema {r['label']}"
        if float(r["C_allow"]) == 0:
            rows.append(row("S20/S22", tag, "Category-C records", "C_allow", 0, c_n,
                            "N = Category-C records", "realistic_schema_results.csv",
                            "summary_recorded_N"))
        if float(r["U_allow"]) == 0:
            rows.append(row("S20/S22", tag, "Category-U records", "U_allow", 0, u_n,
                            "N = Category-U records", "realistic_schema_results.csv",
                            "summary_recorded_N"))
        if float(r["cert_false_allow"]) == 0:
            rows.append(row("S20/S22", tag, "certified-allow decisions", "cert_false_allow",
                            0, allow_n, "N = certified-allow decisions = round(R_allow*R_count)",
                            "realistic_schema_results.csv", "summary_recorded_N"))


def rows_exp1(rows):
    """EXP1 neighbor head-to-head (real IEEE-CIS + OPA policy) — witness-set zero cells."""
    path = os.path.join(OUT, "exp1_neighbor_head_to_head.csv")
    if not os.path.exists(path):
        return
    recs = _load_csv(path)
    # Witness set W: mean 6032 exploit witnesses over 5 seeds (RESULTS TIER 8 / EXP1).
    # Use the conservative rounded mean as the attack_false_allow denominator.
    W = 6032
    for r in recs:
        if r["row"] in ("exact_rung1", "certified_rs") and float(r["attack_false_allow_mean"]) == 0.0:
            rows.append(row("T2-EXP1", f"EXP1 {r['row']} ({r['cell']})",
                            "exploit witnesses W", "attack_false_allow", 0, W,
                            "N = in-budget exploit witnesses W (mean 6032/10000 over 5 seeds)",
                            "exp1_neighbor_head_to_head.csv", "summary_recorded_N"))


# --------------------------------------------------------------------------- #
def main():
    rows = []
    rows_certificates(rows)
    rows_grouped_exec(rows, "e2e_exploit_results.jsonl", "T6-e2e#29",
                      {"joint_cert", "oracle"},
                      {"c_witness", "mixed", "clean"}, "e2e#29")
    rows_grouped_exec(rows, "agent_experiment_results.jsonl", "S8-agent",
                      {"certified", "oracle"},
                      {"c_witness", "mixed", "clean"}, "agent-loop")
    rows_reg(rows)
    rows_nab(rows)
    rows_opa_full(rows)
    rows_realistic(rows)
    rows_exp1(rows)

    os.makedirs(OUT, exist_ok=True)
    csv_p = os.path.join(OUT, "wilson_zero_cells.csv")
    cols = ["table", "setting", "cell", "metric", "k", "N", "rate",
            "wilson95_upper", "cp95_upper", "denominator_semantics", "source", "evidence"]
    with open(csv_p, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    md_p = os.path.join(OUT, "wilson_zero_cells.md")
    with open(md_p, "w") as fh:
        fh.write("# M1 — Wilson-95% upper bounds + explicit n/N for every zero cell\n\n")
        fh.write("every quoted zero now carries a "
                 "numerator, a denominator, and a Wilson-95% upper bound, with the "
                 "denominator semantics stated so the four denominators cannot be "
                 "conflated. `cp95_upper` = exact Clopper-Pearson cross-check.\n\n")
        fh.write(f"**{len(rows)} zero cells audited.** All k=0 except where noted; "
                 "no result value changes (this is post-processing).\n\n")
        fh.write("| table | setting | metric | k/N | Wilson-95% upper | CP-95% upper | denominator | evidence |\n")
        fh.write("|---|---|---|---|---|---|---|---|\n")
        for r in rows:
            fh.write(f"| {r['table']} | {r['setting']} | `{r['metric']}` | "
                     f"{r['k']}/{r['N']} | {r['wilson95_upper']:.4g} | "
                     f"{r['cp95_upper']:.4g} | {r['denominator_semantics']} | {r['evidence']} |\n")
        # headline: tightest and loosest bound
        if rows:
            tight = min(rows, key=lambda r: r["wilson95_upper"])
            loose = max(rows, key=lambda r: r["wilson95_upper"])
            fh.write(f"\n**Range.** Tightest zero-cell bound: `{tight['metric']}` at "
                     f"{tight['setting']} — Wilson-95% upper {tight['wilson95_upper']:.4g} "
                     f"(N={tight['N']}). Loosest: `{loose['metric']}` at {loose['setting']} — "
                     f"Wilson-95% upper {loose['wilson95_upper']:.4g} (N={loose['N']}).\n")
    print(f"wrote {csv_p}")
    print(f"wrote {md_p}")
    print(f"{len(rows)} zero cells audited")
    if rows:
        loose = max(rows, key=lambda r: r["wilson95_upper"])
        print(f"loosest Wilson-95% upper: {loose['wilson95_upper']:.4g} "
              f"(N={loose['N']}, {loose['setting']}/{loose['metric']})")


if __name__ == "__main__":
    main()
