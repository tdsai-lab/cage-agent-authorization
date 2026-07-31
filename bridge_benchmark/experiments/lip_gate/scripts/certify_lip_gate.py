#!/usr/bin/env python3
"""certify_lip_gate.py — CLI: train (or use) a LipGate and report the DETERMINISTIC margin certificate
on a category-balanced eval set: cert_recovery_vs_exact (R_allow), C_allow/U_allow, and empirical
oracle cert_false_allow. Demonstrates Allow_Lip = [min_{s'∈N_d(s)} h(s',x,a) > L·ε]."""
from __future__ import annotations
import argparse, sys, warnings
from pathlib import Path
import numpy as np
warnings.filterwarnings("ignore")
_EXP = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_EXP / "models"))
import lip_gate as LG  # noqa: E402

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domain", default="finance")
    ap.add_argument("--variant", default="robust-aug")
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--n-train", type=int, default=1500)
    ap.add_argument("--n-eval", type=int, default=400)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    orc = LG.OpaOracle(args.domain); enc = LG.make_encoder(orc.rt)
    train = LG.sample_records(args.domain, args.n_train, seed=args.seed)
    ev = LG.sample_records(args.domain, args.n_eval, seed=args.seed + 1)
    model = LG.train_lipgate(orc, enc, train, variant=args.variant, seed=args.seed)
    cats, status = LG.exact_categories(orc, ev, args.eps)
    by = {"R": [], "C": [], "U": []}
    cfa = [0, 0]
    for c, r in zip(cats, ev):
        if c["category"] in by:
            allow = LG.certify_lip(model, enc, orc.rt, r, args.eps)["allow"]
            by[c["category"]].append(int(allow))
            if allow:
                cfa[1] += 1; cfa[0] += int(c["truly_unsafe_reachable"])
    rec = round(float(np.mean(by["R"])), 4) if by["R"] else float("nan")
    print(f"{args.domain} eps={args.eps} status={status} | cert_recovery_vs_exact(R_allow)={rec} "
          f"C_allow={round(float(np.mean(by['C'])),4) if by['C'] else 'na'} "
          f"U_allow={round(float(np.mean(by['U'])),4) if by['U'] else 'na'} "
          f"cert_false_allow={round(cfa[0]/cfa[1],4) if cfa[1] else 0.0}")

if __name__ == "__main__":
    main()
