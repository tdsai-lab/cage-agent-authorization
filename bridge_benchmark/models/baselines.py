#!/usr/bin/env python3
"""
baselines.py — classifier baselines for the learned gate h_theta(z, a) in {0,1} (1 = safe to allow).

Models (masked feature views test expressivity; SPEC sec. 23 / GOAL sec. 7):
    tool_action_only      LogReg on {domain, tool, action}
    categorical_only      LogReg on {domain, action, categorical}
    numeric_only          LogReg on {domain, action, numeric}
    tool_numeric_logistic LogReg on {domain, tool, action, numeric}
    joint_logistic        LogReg on all groups
    joint_mlp             MLP    on all groups
    gradient_boosting     HistGradientBoosting on all groups
    oracle_upper_bound    exact oracle label (ceiling, not trained)

Asymmetric loss: false ALLOW (predict safe on a truly-unsafe point) is penalized more than false
block, via class weights lambda_unsafe > lambda_safe (oversampling where the estimator lacks
class_weight). Reports clean accuracy, safe/unsafe recall, false-allow / false-block, and accuracy by
A/B/C/R/U stratum.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "generators"))
from dataset import FeatureEncoder, build_records  # noqa: E402
from split import stratified_split  # noqa: E402

LAMBDA_UNSAFE, LAMBDA_SAFE = 2.0, 1.0  # PLAN3 sec.5: penalize false allow 2x (tune on val)


class GateModel:
    """Wraps (encoder, estimator) and exposes predictions on arbitrary perturbed points."""

    def __init__(self, name, encoder, estimator, is_oracle=False, rule_table=None):
        self.name = name
        self.enc = encoder
        self.est = estimator
        self.is_oracle = is_oracle
        self.rt = rule_table

    def proba_safe_matrix(self, X):
        return self.est.predict_proba(X)[:, 1]

    def proba_safe_point(self, domain, tool, action, x1, numeric):
        if self.is_oracle:
            from oracle import safe
            z = {"domain": domain, "tool_id": tool, "candidate_action": action,
                 "categorical_fields": x1, "numeric_fields": numeric}
            return 1.0 if safe(z, action, self.rt) else 0.0
        x = np.asarray([self.enc.transform_point(domain, tool, action, x1, numeric)])
        return float(self.est.predict_proba(x)[0, 1])

    def allow_point(self, domain, tool, action, x1, numeric, thr=0.5):
        return self.proba_safe_point(domain, tool, action, x1, numeric) >= thr


def _weighted_fit(estimator, X, y, supports_class_weight, supports_sample_weight):
    w = np.where(y == 0, LAMBDA_UNSAFE, LAMBDA_SAFE)
    if supports_sample_weight:
        estimator.fit(X, y, sample_weight=w)
    elif supports_class_weight:
        estimator.fit(X, y)  # class_weight set in constructor
    else:
        # oversample the unsafe (penalized) class by replication to emulate the weight ratio
        reps = int(round(LAMBDA_UNSAFE / LAMBDA_SAFE))
        idx = np.concatenate([np.arange(len(y))] + [np.where(y == 0)[0]] * (reps - 1))
        estimator.fit(X[idx], y[idx])
    return estimator


def train_all(records=None, rule_table=None, seed=0):
    if records is None:
        records, rule_table = build_records()
    train, val, test = stratified_split(records)

    specs = {
        "tool_action_only": (("domain", "tool", "action"), "logreg"),
        "categorical_only": (("domain", "action", "categorical"), "logreg"),
        "numeric_only": (("domain", "action", "numeric"), "logreg"),
        "tool_numeric_logistic": (("domain", "tool", "action", "numeric"), "logreg"),
        "joint_logistic": (("domain", "tool", "action", "categorical", "numeric"), "logreg"),
        "joint_mlp": (("domain", "tool", "action", "categorical", "numeric"), "mlp"),
        "gradient_boosting": (("domain", "tool", "action", "categorical", "numeric"), "gb"),
    }
    models = {}
    for name, (groups, kind) in specs.items():
        enc = FeatureEncoder(rule_table, groups=groups).fit_numeric(train)
        Xtr, ytr = enc.matrix(train), np.array([r["y"] for r in train])
        if kind == "logreg":
            est = LogisticRegression(max_iter=2000, class_weight={0: LAMBDA_UNSAFE, 1: LAMBDA_SAFE})
            _weighted_fit(est, Xtr, ytr, True, False)
        elif kind == "mlp":
            est = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=800, random_state=seed)
            _weighted_fit(est, Xtr, ytr, False, False)
        elif kind == "gb":
            est = HistGradientBoostingClassifier(max_iter=300, random_state=seed)
            _weighted_fit(est, Xtr, ytr, False, True)
        models[name] = GateModel(name, enc, est)
    # oracle ceiling
    enc = FeatureEncoder(rule_table).fit_numeric(train)
    models["oracle_upper_bound"] = GateModel("oracle_upper_bound", enc, None, is_oracle=True,
                                             rule_table=rule_table)
    return models, (train, val, test), rule_table


def train_certified_gate(train_records, rule_table, sigma=0.25, n_aug=4, seed=0, hidden=(64, 32)):
    """Pointwise gate s_theta(z,a) ~= Safe(z,a), trained with ORACLE-RELABELLED Gaussian augmentation
    (PLAN3 sec.2/9): each noisy sample z_tilde is relabelled by the analytic oracle, NEVER given the
    clean label. This densifies the decision boundary so the smoothed certificate is less vacuous.
    sigma is in raw numeric units and should match the certification sigma.
    """
    from oracle import safe as oracle_safe
    rng = np.random.default_rng(seed)
    aug = list(train_records)
    for r in train_records:
        dom = r["domain"]
        nf = rule_table["domains"][dom]["numeric_fields"]
        base = r["numeric_fields"]
        a = r["candidate_action"]
        for _ in range(n_aug):
            num = {f: float(base[f]) + float(rng.normal(0.0, sigma)) for f in nf}
            z = {"domain": dom, "tool_id": r["tool_id"], "candidate_action": a,
                 "categorical_fields": r.get("categorical_fields", {}), "numeric_fields": num}
            y = 1 if oracle_safe(z, a, rule_table) else 0   # <-- oracle relabel, not clean label
            aug.append({"domain": dom, "tool_id": r["tool_id"], "candidate_action": a,
                        "categorical_fields": r.get("categorical_fields", {}),
                        "numeric_fields": num, "y": y})
    enc = FeatureEncoder(rule_table).fit_numeric(aug)
    X = enc.matrix(aug)
    y = np.array([r["y"] for r in aug])
    est = MLPClassifier(hidden_layer_sizes=hidden, max_iter=1000, random_state=seed)
    _weighted_fit(est, X, y, False, False)
    return GateModel(f"certified_mlp(sigma={sigma})", enc, est)


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #
def evaluate(model: GateModel, records, thr=0.5):
    y = np.array([r["y"] for r in records])
    if model.is_oracle:
        pred = y.copy()
    else:
        X = model.enc.matrix(records)
        pred = (model.proba_safe_matrix(X) >= thr).astype(int)

    acc = float(np.mean(pred == y))
    safe_mask, unsafe_mask = y == 1, y == 0
    safe_recall = float(np.mean(pred[safe_mask] == 1)) if safe_mask.any() else float("nan")
    unsafe_recall = float(np.mean(pred[unsafe_mask] == 0)) if unsafe_mask.any() else float("nan")
    false_allow = float(np.mean(pred[unsafe_mask] == 1)) if unsafe_mask.any() else 0.0
    false_block = float(np.mean(pred[safe_mask] == 0)) if safe_mask.any() else 0.0

    cats = np.array([r["category"] for r in records])
    by_cat = {}
    for c in ("A", "B", "C", "R", "U"):
        m = cats == c
        by_cat[c] = float(np.mean(pred[m] == y[m])) if m.any() else float("nan")
    return {"clean_acc": acc, "safe_recall": safe_recall, "unsafe_recall": unsafe_recall,
            "false_allow": false_allow, "false_block": false_block, "acc_by_cat": by_cat}


def _fmt(x):
    return "  nan" if x != x else f"{x:5.3f}"


def main():
    models, (train, val, test), rt = train_all()
    print(f"train/val/test = {len(train)}/{len(val)}/{len(test)}  (feature dim full = {models['joint_logistic'].enc.dim})\n")
    hdr = f"{'model':<22} {'cleanAcc':>8} {'falseAllow':>10} {'falseBlock':>10} {'A':>5} {'B':>5} {'C':>5} {'R':>5} {'U':>5}"
    print(hdr); print("-" * len(hdr))
    for name, m in models.items():
        e = evaluate(m, test)
        bc = e["acc_by_cat"]
        print(f"{name:<22} {_fmt(e['clean_acc']):>8} {_fmt(e['false_allow']):>10} {_fmt(e['false_block']):>10} "
              f"{_fmt(bc['A'])} {_fmt(bc['B'])} {_fmt(bc['C'])} {_fmt(bc['R'])} {_fmt(bc['U'])}")
    print("\nRead: numeric_only / categorical_only should lose on C (need the joint of tool+numeric);")
    print("      joint models approach the oracle ceiling. falseAllow penalized 3x in training.")


if __name__ == "__main__":
    main()
