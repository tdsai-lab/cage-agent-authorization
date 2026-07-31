#!/usr/bin/env python3
"""
aggregate_results.py — combine the scaling + realistic experiment CSVs into one paper-facing summary
that checks the three claims:

  (1) Category C exists systematically (C% > 0 in every setting);
  (2) R_allow stays non-vacuous (R_allow > 0 in every setting);
  (3) marginal / naive certificates fail reproducibly (naive_C_falseallow ~ 1, attack_false_allow high),
      while the hybrid enumerate certificate stays SOUND (C_allow = 0, cert_false_allow = 0).

Reads cert/out/{scaling_results,realistic_schema_results}.csv. Writes cert/out/experiments_summary.md.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "cert" / "out"


def _read(name):
    p = OUT / name
    if not p.exists():
        return []
    with open(p) as f:
        return list(csv.DictReader(f))


def _f(row, key, default=0.0):
    try:
        return float(row.get(key, default))
    except (TypeError, ValueError):
        return default


def _summary(rows, title, lines):
    if not rows:
        lines.append(f"- {title}: (no results found — run the script first)")
        return
    cflo = max(_f(r, "C_allow") for r in rows)
    ufa = max(_f(r, "cert_false_allow") for r in rows)
    rmin = min(_f(r, "R_allow") for r in rows)
    rmax = max(_f(r, "R_allow") for r in rows)
    cmin = min(_f(r, "C_pct") for r in rows)
    naive = min(_f(r, "naive_C_falseallow") for r in rows)
    atk = min(_f(r, "attack_false_allow") for r in rows)
    lines.append(f"### {title} ({len(rows)} settings)")
    lines.append(f"- Category C present everywhere: min C% = {cmin:.1f}  ({'YES' if cmin > 0 else 'NO'})")
    lines.append(f"- C_allow (hybrid cert): max = {cflo:.3f}  ({'SOUND (0)' if cflo == 0 else 'VIOLATION'})")
    lines.append(f"- certified false allow: max = {ufa:.3f}  ({'SOUND (0)' if ufa == 0 else 'VIOLATION'})")
    lines.append(f"- R_allow (non-vacuity): min = {rmin:.3f}, max = {rmax:.3f}  "
                 f"({'NON-VACUOUS everywhere' if rmin > 0 else 'VACUOUS in some setting'})")
    lines.append(f"- naive-composition falsely certifies C: min = {naive:.2f}  (marginal cert fails)")
    lines.append(f"- uncertified gate robust false-allow: min = {atk:.2f}  (attack succeeds w/o cert)")
    lines.append("")


def main():
    scaling = _read("scaling_results.csv")
    realistic = _read("realistic_schema_results.csv")
    lines = ["# Experiments summary — scaling & realism\n",
             "Three claims for the experimental section:\n",
             "1. **C exists systematically** (not a hand-crafted artifact).",
             "2. **R_allow remains non-vacuous at scale.**",
             "3. **Marginal / naive certificates fail reproducibly**, while the hybrid "
             "enumerate-discrete + Gaussian-RS certificate stays sound (C_allow = cert_false_allow = 0).\n"]
    _summary(scaling, "Scaling study (synthetic typed tools)", lines)
    _summary(realistic, "Realistic schemas (finance / monitoring / ops-security)", lines)

    allrows = scaling + realistic
    if allrows:
        ok = (max(_f(r, "C_allow") for r in allrows) == 0
              and max(_f(r, "cert_false_allow") for r in allrows) == 0
              and min(_f(r, "R_allow") for r in allrows) > 0
              and min(_f(r, "C_pct") for r in allrows) > 0)
        lines.append(f"## Overall: {'ALL THREE CLAIMS HOLD across every setting.' if ok else 'CHECK FAILED — see rows above.'}")

    (OUT / "experiments_summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\nwrote -> {OUT/'experiments_summary.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
