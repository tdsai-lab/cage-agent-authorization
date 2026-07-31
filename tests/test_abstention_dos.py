"""Tests for T2-9 abstention-DoS experiment (skip-guarded, fast)."""
import json
import sys
from pathlib import Path

import pytest

_root = Path(__file__).resolve().parents[1] / "bridge_benchmark"
sys.path.insert(0, str(_root / "experiments"))

IEEE_PATH = _root / "data" / "realdata" / "ieee_cis_boundary_balanced_s0.jsonl"
pytestmark = pytest.mark.skipif(not IEEE_PATH.exists(), reason="IEEE-CIS pool not present")


@pytest.fixture(scope="module")
def mod():
    import abstention_dos as ad
    return ad


@pytest.fixture(scope="module")
def pool(mod):
    import numpy as np
    recs = mod.load_pool(n=2000)
    margins = np.array([mod.oracle_margin(r) for r in recs])
    return recs, margins


def test_adversarial_selection_inflates_abstention(mod, pool):
    """(a) boundary-seeking selection inflates abstention vs benign (inflation > 1)."""
    import numpy as np
    recs, margins = pool
    rng = np.random.default_rng(0)
    ben = mod.benign_selection(recs, margins, rng, 1000)
    adv = mod.adversarial_selection(recs, margins, rng, 1000, strength=1.0)
    ab_ben = mod.batch_metrics(ben, mod.EPS)["abstain_rate"]
    ab_adv = mod.batch_metrics(adv, mod.EPS)["abstain_rate"]
    assert ab_adv > ab_ben
    assert ab_adv / max(ab_ben, 1e-9) > 1.0


def test_soundness_invariant(mod, pool):
    """(b) cert_false_allow == 0 under BOTH benign and adversarial selection."""
    import numpy as np
    recs, margins = pool
    rng = np.random.default_rng(1)
    ben = mod.benign_selection(recs, margins, rng, 1000)
    adv = mod.adversarial_selection(recs, margins, rng, 1000, strength=1.0)
    assert mod.batch_metrics(ben, mod.EPS)["cert_false_allow"] == 0.0
    assert mod.batch_metrics(adv, mod.EPS)["cert_false_allow"] == 0.0


def test_mitigation_reduces_inflation(mod, pool):
    """(c) both mitigations reduce the human-circuit abstention load, and stay sound."""
    import numpy as np
    recs, margins = pool
    rng = np.random.default_rng(2)
    adv = mod.adversarial_selection(recs, margins, rng, 1000, strength=1.0)
    base_abstain = mod.batch_metrics(adv, mod.EPS)["abstain_rate"]

    rl = mod.mitigate_rate_limit(adv, mod.EPS, budget_frac=0.15)
    assert rl["human_abstain_load"] < base_abstain
    assert rl["cert_false_allow"] == 0.0

    ada = mod.mitigate_adaptive_eps(adv, mod.EPS, eps_min=0.02)
    assert ada["abstain_rate"] < base_abstain
    assert ada["cert_false_allow_advertised"] == 0.0


def test_quick_run_emits_files(mod, tmp_path):
    """(d) quick run emits the four output files with valid content."""
    summary = mod.run(seeds=[0, 1], n=400, eps=mod.EPS, strengths=[0.5, 1.0],
                      out_dir=str(tmp_path), quick=True)
    for name in ("inflation.csv", "mitigation.csv", "summary.json", "summary.md"):
        assert (tmp_path / name).exists() and (tmp_path / name).stat().st_size > 0
    j = json.loads((tmp_path / "summary.json").read_text())
    assert j["soundness_invariant"]["cert_false_allow_max_over_all_conditions"] == 0.0
    assert j["baseline_strong_attack"]["inflation_factor"] > 1.0
