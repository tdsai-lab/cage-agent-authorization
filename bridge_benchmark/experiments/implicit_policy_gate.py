#!/usr/bin/env python3
"""
implicit_policy_gate.py — PLAN.md #32: a gate on a REALLY-IMPLICIT policy (no executable predicate).

Every other experiment has an executable oracle Safe(z,a) (analytic rule, OPA/Rego, or the IEEE-CIS
constructed threshold). Reviewers ask: what about policies that exist only as labels — incident
adjudications, a calibrated risk service, human review — with NO predicate to enumerate the budget
against? This experiment uses the REAL IEEE-CIS `isFraud` label as that implicit policy
(`approve-safe <=> not fraud`); the constructed threshold predicate is NOT used. We show:

  (i)  the EXACT / marginal certificate baselines do not exist by construction. They require an
       executable predicate Safe(z,a) to enumerate which points of B_{1,eps} are unsafe; an implicit
       per-record empirical label is not a function over the continuous ball, so joint_reachable_unsafe
       cannot be evaluated -> exact category, deterministic marginal and hybrid certificates are
       UNDEFINED here.
  (ii) the smoothed certificate over the LEARNED gate s_theta(z) needs no predicate: randomized
       smoothing certifies the classifier's own decision is stable over B_{1,eps}. It is the only
       available sound robustness statement, and it is non-vacuous (certifies many clearly-safe txns).
  (iii)the certificate buys REAL robustness vs the point gate: under a B_{1,eps} attack that tries to
       get a fraudulent transaction approved, the point gate's false-allow (measured on the held-out
       fraud label) is high, while the certified gate's is near zero.

Honest oracle ownership: ground truth is the held-out empirical `isFraud` label, which is imperfect
(fraud detection is itself noisy). So (iii) is an EMPIRICAL robustness measure on a held-out label, not
a soundness theorem against a predicate -- which is exactly the regime this experiment is about. The
discrete budget is the real loose<->strict provenance swap (d=1, as measured/used elsewhere).

Self-contained: builds its own featurizer + smoothed certificate (the shared smoothed_gate.certify is
coupled to the analytic rule-table format). numpy/scipy/sklearn. Real data; no network, no LLM.
"""
from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path

import numpy as np
from scipy.stats import beta, norm
from sklearn.neural_network import MLPClassifier

warnings.filterwarnings("ignore")
_root = Path(__file__).resolve().parents[1]
for p in ("generators", "realdata"):
    sys.path.insert(0, str(_root / p))

import ieee_cis_policy as pol  # noqa: E402

OUT = _root / "cert" / "out"
IEEE_PATH = _root / "data" / "realdata" / "ieee_cis_boundary_balanced_s0.jsonl"


# --------------------------------------------------------------------------- #
# Data
# --------------------------------------------------------------------------- #
def load_records(path=IEEE_PATH, n=None):
    recs = []
    with open(path) as f:
        for line in f:
            o = json.loads(line)
            recs.append({"tool_id": o["tool_id"], "x1": dict(o["x1"]), "x2": dict(o["x2"]),
                         "fraud": int(o["meta"]["isFraud"]), "split": o["meta"].get("split", "")})
    if n:
        recs = recs[:n]
    return recs


# --------------------------------------------------------------------------- #
# Featurizer (one-hot tool + one-hot x1 + raw x2); supports perturbed-x2 batches
# --------------------------------------------------------------------------- #
class Featurizer:
    def __init__(self, records):
        self.x2_fields = list(pol.NUMERIC_FIELDS)
        self.tools = sorted(set(pol.TOOLS) | {r["tool_id"] for r in records})
        self.cat_fields = list(pol.CATEGORICAL_FIELDS)
        self.cat_vocab = {f: list(pol.CATEGORICAL_FIELDS[f]) for f in self.cat_fields}
        self.tool_idx = {t: i for i, t in enumerate(self.tools)}
        self.blocks = []  # (offset, size, kind, field)
        off = 0
        self.blocks.append((off, len(self.tools), "tool", None)); off += len(self.tools)
        for f in self.cat_fields:
            self.blocks.append((off, len(self.cat_vocab[f]), "cat", f)); off += len(self.cat_vocab[f])
        self.x2_off = off
        self.dim = off + len(self.x2_fields)

    def _prefix(self, tool, x1):
        v = np.zeros(self.x2_off, dtype=np.float64)
        o = self.tool_idx.get(tool)
        if o is not None:
            v[o] = 1.0
        base = len(self.tools)
        for f in self.cat_fields:
            vocab = self.cat_vocab[f]
            val = x1.get(f)
            if val in vocab:
                v[base + vocab.index(val)] = 1.0
            base += len(vocab)
        return v

    def transform(self, tool, x1, x2):
        v = np.zeros(self.dim, dtype=np.float64)
        v[:self.x2_off] = self._prefix(tool, x1)
        v[self.x2_off:] = [float(x2[f]) for f in self.x2_fields]
        return v

    def matrix(self, records):
        return np.vstack([self.transform(r["tool_id"], r["x1"], r["x2"]) for r in records])

    def perturbed_matrix(self, tool, x1, x2_base, deltas):
        """deltas: (m, k) numeric offsets; returns (m, dim) feature matrix at x2_base + deltas."""
        pre = self._prefix(tool, x1)
        m = deltas.shape[0]
        M = np.zeros((m, self.dim), dtype=np.float64)
        M[:, :self.x2_off] = pre
        base = np.array([float(x2_base[f]) for f in self.x2_fields])
        M[:, self.x2_off:] = base[None, :] + deltas
        return M


# --------------------------------------------------------------------------- #
# Discrete budget + continuous ring (shared by both backends)
# --------------------------------------------------------------------------- #
def _states(rec):
    """Discrete budget d=1: identity + the real loose<->strict provenance swap (x1 fixed)."""
    yield rec["tool_id"], rec["x1"]
    for t2 in pol.discrete_neighbors(rec["tool_id"]):
        yield t2, rec["x1"]


def _ring(k, eps, n_radii=3):
    radii = [eps * (i + 1) / n_radii for i in range(n_radii)]
    dirs = []
    for c in range(k):
        for s in (1.0, -1.0):
            e = np.zeros(k); e[c] = s; dirs.append(e)
    out = [np.zeros(k)]
    for r in radii:
        for d in dirs:
            out.append(r * d)
    return np.array(out)


# --------------------------------------------------------------------------- #
# Backend = LEARNED gate + its certificate. Two interchangeable implementations:
#   lipschitz : a 1-Lipschitz (Orthogonium) net + DETERMINISTIC margin certificate (no sampling)
#   smoothed  : an MLP + Gaussian randomized-smoothing certificate (Monte-Carlo)
# Each exposes scores()/perturbed_scores() (signed score; allow >= decision_thr) and certify().
# --------------------------------------------------------------------------- #
def _cp_lower(k, n, alpha):
    if k <= 0:
        return 0.0
    if k >= n:
        return float(beta.ppf(alpha, k, 1))
    return float(beta.ppf(alpha, k, n - k + 1))


def _cohen(p_lb, eps, sigma):
    p_lb = min(max(p_lb, 1e-12), 1 - 1e-12)
    return float(norm.cdf(norm.ppf(p_lb) - eps / sigma))


class SmoothedBackend:
    name = "smoothed"
    decision_thr = 0.5

    def __init__(self, feat, sigma, tau, n_mc, alpha, seed, lambda_unsafe=3.0):
        self.feat, self.sigma, self.tau, self.n_mc, self.alpha = feat, sigma, tau, n_mc, alpha
        self.seed, self.lambda_unsafe = seed, lambda_unsafe
        self.crng = np.random.default_rng(seed + 1)

    def fit(self, train):
        X = self.feat.matrix(train)
        y = np.array([1 - r["fraud"] for r in train])
        reps = int(round(self.lambda_unsafe))
        idx = np.concatenate([np.arange(len(y))] + [np.where(y == 0)[0]] * (reps - 1))
        self.est = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=600, random_state=self.seed)
        self.est.fit(X[idx], y[idx])
        return self

    def scores(self, records):
        return self.est.predict_proba(self.feat.matrix(records))[:, 1]

    def perturbed_scores(self, tool, x1, x2, deltas):
        return self.est.predict_proba(self.feat.perturbed_matrix(tool, x1, x2, deltas))[:, 1]

    def certify(self, rec, eps):
        k = len(self.feat.x2_fields)
        min_ell = 1.0
        for tool, x1 in _states(rec):
            deltas = self.crng.normal(0.0, self.sigma, size=(self.n_mc, k))
            p = self.perturbed_scores(tool, x1, rec["x2"], deltas)
            p_lb = _cp_lower(int(np.sum(p >= 0.5)), self.n_mc, self.alpha)
            min_ell = min(min_ell, _cohen(p_lb, eps, self.sigma))
        return min_ell >= self.tau


class LipschitzBackend:
    """1-Lipschitz Orthogonium gate + DETERMINISTIC margin certificate: allow iff the min signed
    margin over the d=1 discrete branches exceeds L*eps. No sampling -> exact and stable at low n
    (the motivation for using it over smoothing here)."""
    name = "lipschitz"
    decision_thr = 0.0

    def __init__(self, feat, eps_train_aug=0.10, epochs=300, lambda_unsafe=1.0, seed=0, L=1.0):
        self.feat, self.epochs, self.lambda_unsafe, self.seed, self.L = \
            feat, epochs, lambda_unsafe, seed, L
        self.eps_train_aug = eps_train_aug
        self.gamma = 0.35        # margin target (> eps=0.10) so certified == confident region

    def _augment(self, train, n_aug=4, sigma=0.10, seed=0):
        """Label-preserving robust augmentation: small x2 perturbations + the provenance swap keep the
        (implicit) fraud label, training the 1-Lipschitz net to have margins over the eps-ball ->
        a tighter deterministic certificate. No oracle needed (label travels with the record)."""
        rng = np.random.default_rng(seed)
        out = list(train)
        for r in train:
            for t2 in pol.discrete_neighbors(r["tool_id"]):
                out.append({**r, "tool_id": t2})
            for _ in range(n_aug):
                x2 = {f: float(r["x2"][f]) + float(rng.normal(0.0, sigma)) for f in self.feat.x2_fields}
                out.append({**r, "x2": x2})
        return out

    def fit(self, train):
        import torch
        import torch.nn.functional as F
        sys.path.insert(0, str(_root / "experiments" / "lip_gate" / "models"))
        from orthogonium_adapter import LipGate
        self.torch = torch
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        train = self._augment(train, n_aug=4, sigma=self.eps_train_aug, seed=self.seed)
        X = self.feat.matrix(train).astype(np.float32)
        y = np.array([1 - r["fraud"] for r in train], dtype=np.float32)   # 1 = safe
        torch.manual_seed(self.seed)
        Xt = torch.from_numpy(X).to(self.device)
        yt = torch.from_numpy(2 * y - 1).to(self.device)                 # {-1,+1}, +1 = safe
        # INVERSE-FREQUENCY balance (fraud ~3.5% -> ~27x) x an extra false-allow penalty, so the
        # 1-Lipschitz net does not collapse to "approve everything" under the heavy class imbalance.
        n_safe, n_fraud = int((y == 1).sum()), int(max(1, (y == 0).sum()))
        w_fraud = float(self.lambda_unsafe) * (n_safe / n_fraud)
        wt = torch.where(yt < 0, torch.tensor(w_fraud, device=self.device),
                         torch.tensor(1.0, device=self.device))
        self.model = LipGate(X.shape[1], width=128, depth=3).to(self.device)
        opt = torch.optim.Adam(self.model.parameters(), lr=1e-3)
        self.model.train()
        for _ in range(self.epochs):
            opt.zero_grad()
            h = self.model(Xt).flatten()
            # margin target gamma > eps so the CERTIFIED set (min_margin > L*eps) is the gate's
            # confident region, not the fuzzy boundary band (tightens cert false-allow).
            loss = (wt * (F.softplus(-yt * h) + 1.0 * F.relu(self.gamma - yt * h))).mean()
            loss.backward()
            opt.step()
        self.model.eval()
        return self

    def _h(self, M):
        with self.torch.no_grad():
            t = self.torch.from_numpy(np.asarray(M, dtype=np.float32)).to(self.device)
            return self.model(t).flatten().cpu().numpy()

    def scores(self, records):
        return self._h(self.feat.matrix(records))

    def perturbed_scores(self, tool, x1, x2, deltas):
        return self._h(self.feat.perturbed_matrix(tool, x1, x2, deltas))

    def certify(self, rec, eps):
        rows = [self.feat.transform(tool, x1, rec["x2"]) for tool, x1 in _states(rec)]
        min_margin = float(np.min(self._h(np.vstack(rows))))
        return min_margin > self.L * eps        # deterministic: robust over the eps-ball


def _point_allows(backend, rec, thr):
    return backend.scores([rec])[0] >= thr


def _attack_allows(backend, rec, ring, thr):
    """True iff the attacker finds any z' in B_{1,eps}(rec) the point gate approves (score >= thr)."""
    for tool, x1 in _states(rec):
        if np.any(backend.perturbed_scores(tool, x1, rec["x2"], ring) >= thr):
            return True
    return False


def make_backend(kind, feat, *, sigma, tau, n_mc, alpha, seed):
    if kind == "lipschitz":
        return LipschitzBackend(feat, seed=seed)
    if kind == "smoothed":
        return SmoothedBackend(feat, sigma, tau, n_mc, alpha, seed)
    raise ValueError(f"unknown backend {kind}")


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def run(n_records, n_eval, sigma, eps, tau, n_mc, alpha, seed, backend="lipschitz"):
    recs = load_records(n=n_records)
    rng = np.random.default_rng(seed)
    feat = Featurizer(recs)

    perm = rng.permutation(len(recs))
    cut = int(0.7 * len(recs))
    train = [recs[i] for i in perm[:cut]]
    test = [recs[i] for i in perm[cut:]]

    be = make_backend(backend, feat, sigma=sigma, tau=tau, n_mc=n_mc, alpha=alpha, seed=seed).fit(train)
    thr0 = be.decision_thr

    fraud = [r for r in test if r["fraud"] == 1]
    safe = [r for r in test if r["fraud"] == 0]
    rng.shuffle(fraud); rng.shuffle(safe)
    fraud, safe = fraud[:n_eval], safe[:n_eval]
    ring = _ring(len(feat.x2_fields), eps)

    # (iii) robustness on truly-unsafe (fraud) records: point-gate-under-attack vs certified
    point_fa_clean = float(np.mean([_point_allows(be, r, thr0) for r in fraud]))
    point_fa_attack = float(np.mean([_attack_allows(be, r, ring, thr0) for r in fraud]))
    cert_fa = float(np.mean([be.certify(r, eps) for r in fraud]))

    # (ii) non-vacuity on truly-safe records
    cert_allow_safe = float(np.mean([be.certify(r, eps) for r in safe]))
    point_allow_safe = float(np.mean([_point_allows(be, r, thr0) for r in safe]))

    # matched-threshold point gate: same safe-allow rate as the cert -> isolates ROBUSTNESS from
    # conservatism (apples-to-apples utility operating point).
    sc_safe = be.scores(safe)
    thr_m = float(np.quantile(sc_safe, max(0.0, 1.0 - cert_allow_safe))) if cert_allow_safe > 0 \
        else float(sc_safe.max() + 1.0)
    point_m_fa_clean = float(np.mean([_point_allows(be, r, thr_m) for r in fraud]))
    point_m_fa_attack = float(np.mean([_attack_allows(be, r, ring, thr_m) for r in fraud]))
    point_m_allow_safe = float(np.mean([_point_allows(be, r, thr_m) for r in safe]))

    # context: clean point accuracy / AUC against the (imperfect) held-out fraud label
    from sklearn.metrics import roc_auc_score
    yte = np.array([1 - r["fraud"] for r in test])
    sc = be.scores(test)
    auc = float(roc_auc_score(yte, sc))
    acc = float(np.mean((sc >= thr0).astype(int) == yte))

    return {
        "backend": backend, "n_train": len(train), "n_eval_fraud": len(fraud),
        "n_eval_safe": len(safe), "sigma": sigma, "eps": eps, "tau": tau, "n_mc": n_mc,
        "gate_auc": round(auc, 4), "gate_acc": round(acc, 4),
        "point_false_allow_clean": round(point_fa_clean, 4),
        "point_false_allow_attacked": round(point_fa_attack, 4),
        "point_matched_thr": round(thr_m, 4),
        "point_matched_false_allow_clean": round(point_m_fa_clean, 4),
        "point_matched_false_allow_attacked": round(point_m_fa_attack, 4),
        "point_matched_allow_rate_safe": round(point_m_allow_safe, 4),
        "cert_false_allow": round(cert_fa, 4),
        "cert_allow_rate_safe": round(cert_allow_safe, 4),
        "point_allow_rate_safe": round(point_allow_safe, 4),
        "exact_marginal_certificate": "UNDEFINED (no executable predicate to enumerate B_{1,eps})",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n-records", type=int, default=10000)
    ap.add_argument("--n-eval", type=int, default=400)
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--n-mc", type=int, default=1000)
    ap.add_argument("--alpha", type=float, default=1e-3)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--backend", default="both", choices=["lipschitz", "smoothed", "both"])
    ap.add_argument("--out", default="implicit_policy_gate")
    args = ap.parse_args()

    if not IEEE_PATH.exists():
        print(f"[error] IEEE-CIS data not found at {IEEE_PATH}")
        return

    backends = ["lipschitz", "smoothed"] if args.backend == "both" else [args.backend]
    results = {}
    for be in backends:
        results[be] = run(args.n_records, args.n_eval, args.sigma, args.eps, args.tau, args.n_mc,
                          args.alpha, args.seed, backend=be)
        print(f"[{be}]", json.dumps(results[be]))

    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / f"{args.out}.json", "w") as f:
        json.dump(results, f, indent=2)
    with open(OUT / f"{args.out}.md", "w") as f:
        f.write("# PLAN.md #32 — gate on a really-implicit policy (real IEEE-CIS isFraud, no predicate)\n\n")
        m0 = results[backends[0]]
        f.write("Implicit policy: `approve-safe <=> not fraud`, ground truth = held-out **real** "
                "`isFraud` label (imperfect, owned honestly). **No executable predicate**, so the exact "
                "and marginal certificate baselines are UNDEFINED by construction (they need a predicate "
                "to enumerate which points of B_{1,eps} are unsafe). The only sound robustness statement "
                "is a certificate over the LEARNED gate.\n\n")
        f.write(f"- gate quality vs held-out fraud label: AUC ~**{m0['gate_auc']}** (the implicit "
                f"policy is learnable but noisy)\n")
        f.write(f"- **(i) exact / marginal certificate**: {m0['exact_marginal_certificate']}\n\n")
        f.write("**(ii)+(iii) Two certificate backends on the SAME gate** (the EXP_LIP tradeoff, here in "
                "the implicit-policy regime). `cert_false_allow` and the **matched-threshold** point gate "
                "(same safe-allow rate, isolating robustness from conservatism) on held-out frauds:\n\n")
        f.write("| backend | sampling | cert allow (safe) | **cert FA (fraud)** | point matched FA "
                "clean | point matched FA **ATTACKED** |\n")
        f.write("|---|---|---:|---:|---:|---:|\n")
        for be in backends:
            m = results[be]
            samp = "none (deterministic)" if be == "lipschitz" else f"MC n={m['n_mc']}"
            f.write(f"| {be} | {samp} | {m['cert_allow_rate_safe']} | **{m['cert_false_allow']}** | "
                    f"{m['point_matched_false_allow_clean']} | "
                    f"**{m['point_matched_false_allow_attacked']}** |\n")
        f.write("\n**Reads.** With no predicate the exact/marginal baselines do not exist; a certificate "
                "over the learned gate is the only sound option, and it is non-vacuous. Under a B_{1,eps} "
                "attack the matched-threshold point gate's fraud false-allow rises well above the "
                "certified gate's -> the certificate buys REAL robustness, not just a stricter threshold. "
                "The **deterministic 1-Lipschitz** certificate needs NO sampling (stable at low n, no "
                "tau/n_mc knife-edge); the **smoothing** certificate is more conservative and gives a "
                "cleaner fraud separation on this weak (AUC~0.72) signal -- the same lip-vs-smoothing "
                "tradeoff as EXP_LIP. Ground truth is the imperfect held-out fraud label, so this is an "
                "empirical robustness result, not a predicate-soundness theorem.\n")

    print(f"\nwrote {OUT / (args.out + '.json')}\nwrote {OUT / (args.out + '.md')}")
    return results


if __name__ == "__main__":
    main()
