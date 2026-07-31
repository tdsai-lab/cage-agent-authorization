#!/usr/bin/env python3
"""train_lip_gate.py — CLI: train a 1-Lipschitz LipGate on an OPA authored-Rego domain, record the
claimed Lipschitz constant + an empirical Lipschitz sanity check, and save the model to
results/diagnostics/. Importable building block; the main run uses lip_gate.train_lipgate directly."""
from __future__ import annotations
import argparse, json, sys, warnings
from pathlib import Path
warnings.filterwarnings("ignore")
_EXP = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_EXP / "models"))
import torch  # noqa: E402
import lip_gate as LG  # noqa: E402
from orthogonium_adapter import empirical_lipschitz, backend_name, CLAIMED_L  # noqa: E402

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domain", default="finance")
    ap.add_argument("--variant", default="robust-aug", choices=["small", "medium", "robust-aug"])
    ap.add_argument("--n-train", type=int, default=1500)
    ap.add_argument("--epochs", type=int, default=250)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    DIAG = _EXP / "results" / "diagnostics"; DIAG.mkdir(parents=True, exist_ok=True)
    orc = LG.OpaOracle(args.domain); enc = LG.make_encoder(orc.rt)
    train = LG.sample_records(args.domain, args.n_train, seed=args.seed)
    model = LG.train_lipgate(orc, enc, train, variant=args.variant, epochs=args.epochs, seed=args.seed)
    dim = enc.matrix(train[:1]).shape[1]
    emp = empirical_lipschitz(model, dim, device=LG.DEVICE)
    path = DIAG / f"lipgate_{args.domain}_{args.variant}.pt"
    torch.save(model.state_dict(), path)
    diag = {"domain": args.domain, "variant": args.variant, "backend": backend_name(),
            "claimed_L": CLAIMED_L, "empirical_lipschitz": round(emp, 4), "in_dim": dim,
            "lipschitz_ok": emp <= CLAIMED_L + 1e-3, "model_path": str(path.name),
            "policy_provenance": LG.PROVENANCE}
    (DIAG / f"lipgate_{args.domain}_{args.variant}.json").write_text(json.dumps(diag, indent=2) + "\n")
    print(diag)

if __name__ == "__main__":
    main()
