#!/usr/bin/env python3
"""
split.py — deterministic stratified train/val/test split.

Strata: (domain, candidate_action, category, safety_label). Within each stratum, records are ordered
by id and assigned round-robin to test / val / train at a fixed ratio. Deterministic (no RNG; keyed by
the record id), so splits are reproducible across runs and machines.
"""
from __future__ import annotations

from collections import defaultdict


def stratified_split(records, ratios=(0.6, 0.2, 0.2)):
    assert abs(sum(ratios) - 1.0) < 1e-9
    r_train, r_val, r_test = ratios
    strata = defaultdict(list)
    for r in records:
        key = (r["domain"], r["candidate_action"], r["category"], r["safety_label"])
        strata[key].append(r)

    train, val, test = [], [], []
    for key in sorted(strata):
        items = sorted(strata[key], key=lambda r: r["id"])
        n = len(items)
        n_test = max(1, int(round(n * r_test))) if n >= 3 else 0
        n_val = max(1, int(round(n * r_val))) if n >= 3 else 0
        # deterministic interleave: every k-th item to test/val so strata aren't range-biased
        for i, r in enumerate(items):
            bucket = i % 5  # 3:1:1 -> train,train,train,val,test
            if n < 3:
                train.append(r)
            elif bucket == 4:
                test.append(r)
            elif bucket == 3:
                val.append(r)
            else:
                train.append(r)
    return train, val, test


if __name__ == "__main__":
    from dataset import build_records
    recs, _ = build_records()
    tr, va, te = stratified_split(recs)
    print(f"total {len(recs)} -> train {len(tr)}  val {len(va)}  test {len(te)}")
    from collections import Counter
    for name, s in [("train", tr), ("val", va), ("test", te)]:
        print(f"  {name}: categories {dict(Counter(r['category'] for r in s))}")
