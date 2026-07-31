#!/usr/bin/env python3
"""
opa_oracle.py — OPA-backed Safe(z,a) and the A/B/C/R/U category over the joint ball B_{1,eps}.

Every safe/unsafe verdict is produced by the OPA engine (opa_bridge.eval_batch); Python only enumerates
the exact d=1 discrete neighbors (oracle.discrete_swaps — structural) and the continuous worst-case
probe (policy_field + eps, the unsafe direction for a `field < threshold` policy). All probe points for
all records are evaluated in ONE OPA call per domain.

Category (matches the analytic taxonomy, but decided by OPA):
    U  clean point already unsafe
    A  a 1-step discrete swap ALONE flips safe->unsafe (at the clean numeric point)
    B  an eps continuous move ALONE flips (at the clean discrete state)
    C  neither alone flips, but a JOINT discrete+continuous move flips  (the joint-gap witness)
    R  nothing in B_{1,eps} flips
`truly_unsafe_reachable` == (category != "R").
"""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parents[1] / "generators"))

from oracle import discrete_swaps  # noqa: E402  (structural neighbor enumeration only)
import opa_bridge  # noqa: E402
from schema import DOMAINS, build_rt  # noqa: E402


class OpaOracle:
    def __init__(self, domain: str):
        self.domain = domain
        self.cfg = DOMAINS[domain]
        self.rt = build_rt(domain)
        self.dc = self.rt["domains"][domain]
        self.package = self.cfg["package"]
        self.rego = self.cfg["rego"]
        self.priv = self.cfg["privileged"]
        self.field = self.cfg["policy_field"]
        self.version = opa_bridge.opa_version()
        self.policy_hash = opa_bridge.policy_hash(self.rego)

    # ---- low-level: OPA-format case + batched evaluation ----
    def _case(self, tool, x1, x2, action=None):
        return {"tool": tool, "action": action or self.priv, "x1": x1, "x2": x2}

    def _safe(self, cases):
        return opa_bridge.eval_batch(self.rego, self.package, cases)

    def safe_records(self, records):
        """OPA Safe(z, candidate_action) for each record (one batched call)."""
        cases = [self._case(r["tool_id"], r["categorical_fields"], r["numeric_fields"],
                            r.get("candidate_action")) for r in records]
        return self._safe(cases)

    # ---- category over B_{1,eps}, all records in one OPA call ----
    def categorize(self, records, eps):
        field = self.field
        cases, spans = [], []          # spans[i] = (clean_idx, [disc_idx...], cont_idx, [joint_idx...])
        for r in records:
            tool, x1, x2 = r["tool_id"], r["categorical_fields"], r["numeric_fields"]
            x2c = dict(x2); x2c[field] = float(x2[field]) + eps      # continuous worst case (+eps)
            neigh = list(discrete_swaps(self.dc, tool, x1, 1))       # exact d=1 neighbors
            clean_idx = len(cases); cases.append(self._case(tool, x1, x2))
            disc_idx = []
            for (t2, x12, _n) in neigh:
                disc_idx.append(len(cases)); cases.append(self._case(t2, x12, x2))
            cont_idx = len(cases); cases.append(self._case(tool, x1, x2c))
            joint_idx = []
            for (t2, x12, _n) in neigh:
                joint_idx.append(len(cases)); cases.append(self._case(t2, x12, x2c))
            spans.append((clean_idx, disc_idx, cont_idx, joint_idx))
        verdict = self._safe(cases)
        out = []
        for r, (ci, di, coi, ji) in zip(records, spans):
            clean = verdict[ci]
            disc_flip = any(verdict[k] != clean for k in di)
            cont_flip = verdict[coi] != clean
            joint_flip = any(verdict[k] != clean for k in ji)
            if not clean:
                cat = "U"
            elif disc_flip:
                cat = "A"
            elif cont_flip:
                cat = "B"
            elif joint_flip:
                cat = "C"
            else:
                cat = "R"
            out.append({"clean_safe": bool(clean), "category": cat,
                        "truly_unsafe_reachable": cat != "R",
                        "disc_flip": disc_flip, "cont_flip": cont_flip, "joint_flip": joint_flip})
        return out


if __name__ == "__main__":
    from schema import sample_records
    orc = OpaOracle("finance")
    recs = sample_records("finance", 400, seed=0)
    cats = orc.categorize(recs, eps=0.10)
    from collections import Counter
    c = Counter(x["category"] for x in cats)
    print("opa", orc.version, "hash", orc.policy_hash)
    print("category distribution (finance, n=400, eps=0.10):", dict(c))
