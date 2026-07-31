#!/usr/bin/env python3
"""
dataset.py — labelled dataset + feature encoder for the learned gate h_theta(z, a).

The binary training label is  y(z, a) = 1[ Safe(z, a) ]  from the ANALYTIC oracle (oracle.py).
The interaction category A/B/C/R/U is NOT a training label — it is an evaluation stratum.

Feature map (groups can be masked for baselines):
    phi(z, a) = [ onehot(domain), onehot(tool), onehot(action), onehot(x1 categoricals), x2_standardized ]

Records are built by densely sweeping each (domain, tool, candidate_action, categorical_context) over
a numeric grid and labelling with the oracle. The encoder unifies all domains into one fixed-width
vector (absent numeric fields -> 0 = standardized mean; absent categoricals -> all-zero block), so a
single classifier can be trained across domains while the domain/tool one-hots identify context.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

_GEN = Path(__file__).resolve().parents[1] / "generators"
sys.path.insert(0, str(_GEN))

from oracle import load_rule_table, category, _x1  # noqa: E402

FEATURE_GROUPS = ("domain", "tool", "action", "categorical", "numeric")


# --------------------------------------------------------------------------- #
# Dataset construction (dense oracle sweep)
# --------------------------------------------------------------------------- #
def _frange(lo, hi, step):
    n = int(round((hi - lo) / step))
    return [round(lo + i * step, 4) for i in range(n + 1)]


def _contexts(domain_cfg):
    cats = domain_cfg["categorical_fields"]
    base = {f: vals[0] for f, vals in cats.items()}
    grid = [dict(base)]
    for f, vals in cats.items():
        for v in vals[1:]:
            c = dict(base)
            c[f] = v
            grid.append(c)
    return grid


def _numeric_grid(domain, fine):
    if domain == "financial_compliance":
        step = 0.02 if fine else 0.05
        return [{"risk_score": r, "amount_norm": 0.2} for r in _frange(0.0, 1.0, step)]
    if domain == "system_monitoring":
        step = 0.08 if fine else 0.1
        g = _frange(0.0, 1.0, step)
        return [{"error_rate": er, "latency_norm": lat} for er in g for lat in g]
    raise ValueError(domain)


def build_records(rule_table=None, domains=("financial_compliance", "system_monitoring"),
                  eps=0.10, fine=True):
    rt = rule_table or load_rule_table()
    records = []
    rid = 0
    for domain in domains:
        dc = rt["domains"][domain]
        for action in dc["candidate_actions"]:
            for ctx in _contexts(dc):
                for tool in dc["tools"]:
                    if not any(r["tool_id"] == tool and r["candidate_action"] == action for r in dc["rules"]):
                        continue
                    for num in _numeric_grid(domain, fine):
                        z = {"domain": domain, "tool_id": tool, "candidate_action": action,
                             "categorical_fields": dict(ctx), "numeric_fields": dict(num)}
                        res = category(z, action, rt, d=1, eps=eps)
                        rid += 1
                        records.append({
                            "id": f"{domain[:3]}-{rid:06d}",
                            "domain": domain, "tool_id": tool, "candidate_action": action,
                            "categorical_fields": dict(ctx), "numeric_fields": dict(num),
                            "y": 1 if res["clean_safe"] else 0,
                            "safety_label": "safe" if res["clean_safe"] else "unsafe",
                            "category": res["category"][0],  # A/B/C/R/U short code
                        })
    return records, rt


# --------------------------------------------------------------------------- #
# Feature encoder
# --------------------------------------------------------------------------- #
class FeatureEncoder:
    """Fit vocabularies + numeric standardization on a list of records; transform (z, a) -> vector.

    ``groups`` selects which feature blocks are active (for masked baselines).
    """

    def __init__(self, rule_table, groups=FEATURE_GROUPS):
        self.rt = rule_table
        self.groups = tuple(groups)
        self.domains = sorted(rule_table["domains"])
        self.tools, self.actions = [], []
        self.cat_pairs = []          # (field, value)
        self.numeric_fields = []     # union across domains, sorted
        for dom in self.domains:
            dc = rule_table["domains"][dom]
            self.tools += [(dom, t) for t in dc["tools"]]
            self.actions += [(dom, a) for a in dc["candidate_actions"]]
            for f, vals in dc["categorical_fields"].items():
                self.cat_pairs += [(f, v) for v in vals]
            for nf in dc["numeric_fields"]:
                if nf not in self.numeric_fields:
                    self.numeric_fields.append(nf)
        self.tools = sorted(set(self.tools))
        self.actions = sorted(set(self.actions))
        self.cat_pairs = sorted(set(self.cat_pairs))
        self.numeric_fields = sorted(set(self.numeric_fields))
        self._num_mean = {nf: 0.0 for nf in self.numeric_fields}
        self._num_std = {nf: 1.0 for nf in self.numeric_fields}

    def fit_numeric(self, records):
        for nf in self.numeric_fields:
            vals = [r["numeric_fields"][nf] for r in records if nf in r["numeric_fields"]]
            if vals:
                self._num_mean[nf] = float(np.mean(vals))
                s = float(np.std(vals))
                self._num_std[nf] = s if s > 1e-9 else 1.0
        return self

    def _blocks(self, domain, tool, action, x1, numeric):
        out = []
        if "domain" in self.groups:
            out += [1.0 if domain == d else 0.0 for d in self.domains]
        if "tool" in self.groups:
            out += [1.0 if (domain, tool) == p else 0.0 for p in self.tools]
        if "action" in self.groups:
            out += [1.0 if (domain, action) == p else 0.0 for p in self.actions]
        if "categorical" in self.groups:
            out += [1.0 if x1.get(f) == v else 0.0 for (f, v) in self.cat_pairs]
        if "numeric" in self.groups:
            out += [((float(numeric[nf]) - self._num_mean[nf]) / self._num_std[nf]) if nf in numeric else 0.0
                    for nf in self.numeric_fields]
        return out

    def transform_record(self, r):
        return self._blocks(r["domain"], r["tool_id"], r["candidate_action"],
                            r.get("categorical_fields", {}), r["numeric_fields"])

    def transform_point(self, domain, tool, action, x1, numeric):
        return self._blocks(domain, tool, action, x1, numeric)

    def matrix(self, records):
        return np.asarray([self.transform_record(r) for r in records], dtype=np.float64)

    @property
    def dim(self):
        return len(self._blocks(self.domains[0], self.tools[0][1], self.actions[0][1], {}, {}))

    def numeric_block(self):
        """Return (start_index, field_list, mean_array, std_array) for the numeric block, which is the
        LAST block in the feature vector. Lets randomized smoothing overwrite numeric columns in a
        tiled matrix instead of re-encoding each Monte-Carlo sample. Raises if numeric is masked out."""
        if "numeric" not in self.groups:
            raise ValueError("numeric group not active in this encoder")
        start = self.dim - len(self.numeric_fields)
        mean = np.array([self._num_mean[nf] for nf in self.numeric_fields])
        std = np.array([self._num_std[nf] for nf in self.numeric_fields])
        return start, list(self.numeric_fields), mean, std


if __name__ == "__main__":
    recs, rt = build_records()
    from collections import Counter
    print(f"records: {len(recs)}")
    print("by category:", dict(Counter(r["category"] for r in recs)))
    print("by label   :", dict(Counter(r["safety_label"] for r in recs)))
    enc = FeatureEncoder(rt).fit_numeric(recs)
    print(f"feature dim (full): {enc.dim}")
    for g in [("domain", "tool", "action"), ("domain", "action", "numeric")]:
        print(f"  dim {g}: {FeatureEncoder(rt, groups=g).dim}")
