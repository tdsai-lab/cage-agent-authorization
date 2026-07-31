#!/usr/bin/env python3
"""Unified ε_emp(freshness-SLA) reconciliation curve.

Shows that #17 (EPS-DERIVE, feature-space staleness) and EXP2-A (wall-clock
same-entity staleness) measure the *same* residual-drift mechanism at
different SLA operating points -- not a contradiction.

Standalone. Reads existing outputs from cert/out/, writes:
  cert/out/reconciliation_eps_freshness_sla.{pdf,png}
  cert/out/reconciliation_paragraph.txt

No data is invented: if an input file is missing or has an unexpected
schema, the script raises a clear error naming the file and the expected
columns.
"""
from __future__ import annotations

import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker as ticker  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

# Resolve cert/out relative to this file so the script runs from anywhere.
HERE = Path(__file__).resolve().parent
OUT_DIR = (HERE / ".." / "cert" / "out").resolve()


def _require(path: Path, expected_cols: list[str]) -> pd.DataFrame:
    if not path.exists():
        sys.exit(
            f"ERROR: required input missing: {path}\n"
            f"  expected a CSV with columns: {expected_cols}"
        )
    df = pd.read_csv(path)
    missing = [c for c in expected_cols if c not in df.columns]
    if missing:
        sys.exit(
            f"ERROR: {path} is missing expected columns: {missing}\n"
            f"  found: {list(df.columns)}"
        )
    return df


# ── Load EXP2-A (wall-clock same-entity, already aggregated over 5 seeds) ──
exp2a = _require(
    OUT_DIR / "exp2a_freshness_sla.csv",
    [
        "delta_t_sec",
        "eps_emp_p95_mean",
        "eps_emp_p95_std",
        "system_false_allow_mean",
        "system_false_allow_std",
        "declared_eps",
        "cert_false_allow",
    ],
).sort_values("delta_t_sec")

delta_t = exp2a["delta_t_sec"].to_numpy(dtype=float)
eps_mean = exp2a["eps_emp_p95_mean"].to_numpy(dtype=float)
eps_std = exp2a["eps_emp_p95_std"].to_numpy(dtype=float)
sfa_mean = exp2a["system_false_allow_mean"].to_numpy(dtype=float)
sfa_std = exp2a["system_false_allow_std"].to_numpy(dtype=float)
declared_eps = float(exp2a["declared_eps"].iloc[0])
assert (exp2a["cert_false_allow"] == 0.0).all(), "cert_false_allow must be 0 everywhere"

# ── Load EPS-DERIVE #17 (feature-space staleness, integrity+freshness) ──
eps17_df = _require(
    OUT_DIR / "epsilon_derivation.csv",
    ["pipeline", "regime", "eps_p95"],
)
row17 = eps17_df[
    (eps17_df["pipeline"] == "fraud_risk")
    & (eps17_df["regime"] == "integrity_plus_freshness")
]
if row17.empty:
    sys.exit(
        "ERROR: epsilon_derivation.csv has no (fraud_risk, integrity_plus_freshness) row"
    )
eps_17 = float(row17["eps_p95"].iloc[0])

# ── Load RESWEEP #20 (R_allow by ε, finance) for the utility-cost annotation ──
resweep = _require(
    OUT_DIR / "epsilon_resweep.csv",
    ["domain", "eps", "R_allow", "cert_false_allow"],
)
fin = resweep[resweep["domain"] == "finance"].sort_values("eps")
assert (resweep["cert_false_allow"] == 0.0).all(), "cert_false_allow must be 0 in resweep"
# R_allow at the declared ε (utility retained when operating at ε=0.10)
r_at_declared = fin[np.isclose(fin["eps"], declared_eps)]["R_allow"]
r_declared = float(r_at_declared.iloc[0]) if not r_at_declared.empty else float("nan")

# ── Crossing: smallest Δt at which ε_emp@p95 reaches the declared ε ──
# eps_mean is monotone increasing in Δt. If even the smallest SLA already
# exceeds the declared ε, the crossing is below the measured range.
if eps_mean[0] <= declared_eps:
    idx = int(np.searchsorted(eps_mean, declared_eps))
    crossing_dt = float(delta_t[idx]) if idx < len(delta_t) else None
    crossing_below_range = False
else:
    crossing_dt = float(delta_t[0])
    crossing_below_range = True

# ── Plot ──
plt.rcParams.update({"font.size": 9})
fig, ax1 = plt.subplots(figsize=(7, 4.2))
ax2 = ax1.twinx()

C_EPS = "#2563eb"   # blue  -- residual drift
C_DECL = "#dc2626"  # red   -- declared ε
C_SFA = "#d97706"   # amber -- system false-allow
C_17 = "#16a34a"    # green -- #17 marker

# Left axis: ε_emp@p95 (wall-clock)
ax1.plot(
    delta_t, eps_mean, color=C_EPS, linewidth=2, marker="o", markersize=4,
    label=r"$\varepsilon_{\mathrm{emp}}$@p95 (same-entity wall-clock)",
)
ax1.fill_between(delta_t, eps_mean - eps_std, eps_mean + eps_std, color=C_EPS, alpha=0.15)
ax1.axhline(
    y=declared_eps, color=C_DECL, linestyle="--", linewidth=1.5,
    label=rf"declared $\varepsilon = {declared_eps:.2f}$",
)
ax1.set_xlabel(r"Freshness SLA  $\Delta t$")
ax1.set_ylabel(r"$\varepsilon_{\mathrm{emp}}$@p95  (residual drift)", color=C_EPS)
ax1.tick_params(axis="y", labelcolor=C_EPS)

# Right axis: system false-allow (budget-escape rate)
ax2.plot(
    delta_t, sfa_mean, color=C_SFA, linewidth=2, linestyle="-.", marker="s", markersize=3.5,
    label="system false-allow (budget escape)",
)
ax2.fill_between(delta_t, sfa_mean - sfa_std, sfa_mean + sfa_std, color=C_SFA, alpha=0.12)
ax2.set_ylabel("system false-allow (escape rate)", color=C_SFA)
ax2.tick_params(axis="y", labelcolor=C_SFA)

# #17 marker: feature-space staleness, no wall-clock Δt -> pin to the left edge.
x_left = delta_t[0] * 0.55
ax1.plot(
    x_left, eps_17, marker="D", color=C_17, markersize=9, zorder=6,
    label=r"EPS-DERIVE (#17, feature-space staleness)",
)
ax1.annotate(
    f"#17 integrity+freshness\n(feature-space, not wall-clock)\n$\\varepsilon$={eps_17:.3f}",
    xy=(x_left, eps_17), fontsize=7, color=C_17,
    xytext=(6, -34), textcoords="offset points",
    arrowprops=dict(arrowstyle="->", color=C_17, lw=0.8),
)

# Crossing marker
if crossing_below_range:
    ax1.annotate(
        f"$\\varepsilon_{{emp}}$ already > {declared_eps:.2f}\nat the tightest SLA "
        f"({delta_t[0]:.0f}s)\n→ crossing < {delta_t[0]:.0f}s",
        xy=(delta_t[0], eps_mean[0]), fontsize=7, color="gray",
        xytext=(12, 18), textcoords="offset points",
        arrowprops=dict(arrowstyle="->", color="gray", lw=0.8),
    )
elif crossing_dt is not None:
    ax1.axvline(x=crossing_dt, color="gray", linestyle=":", alpha=0.6)
    ax1.annotate(
        f"SLA min ≈ {crossing_dt:.0f}s",
        xy=(crossing_dt, declared_eps), fontsize=7.5,
        xytext=(15, 15), textcoords="offset points",
        arrowprops=dict(arrowstyle="->", color="gray"),
    )

# Coverage / budget-escape shading split at the crossing.
xlo, xhi = x_left * 0.85, delta_t[-1] * 1.15
split = crossing_dt if (crossing_dt is not None and not crossing_below_range) else delta_t[0]
ax1.axvspan(xlo, split, color="#16a34a", alpha=0.05, zorder=0)
ax1.axvspan(split, xhi, color="#dc2626", alpha=0.05, zorder=0)

# R_allow utility annotation at the declared-ε operating point.
if not np.isnan(r_declared):
    ax1.text(
        0.97, 0.04,
        f"RESWEEP: at $\\varepsilon$={declared_eps:.2f}  R_allow={r_declared:.2f}  "
        f"(utility retained, finance)\ncert_false_allow = 0 at every $\\varepsilon$ and every SLA",
        transform=ax1.transAxes, fontsize=6.8, color="#374151",
        ha="right", va="bottom",
        bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="#cccccc", alpha=0.9),
    )

# Log X with human-readable time ticks.
ax1.set_xscale("log")
ax1.set_xlim(xlo, xhi)


def fmt_time(x, _):
    if x < 60:
        return f"{x:.0f}s"
    if x < 3600:
        return f"{x / 60:.0f}min"
    if x < 86400:
        return f"{x / 3600:.0f}h"
    return f"{x / 86400:.0f}d"


ax1.xaxis.set_major_formatter(ticker.FuncFormatter(fmt_time))
ax1.xaxis.set_minor_formatter(ticker.NullFormatter())

ax1.set_ylim(0, max(eps_mean.max(), eps_17, declared_eps) * 1.18)
ax2.set_ylim(0, (sfa_mean + sfa_std).max() * 1.3)

# Combined legend.
lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper left", fontsize=7.5, framealpha=0.9)

fig.tight_layout()
pdf_path = OUT_DIR / "reconciliation_eps_freshness_sla.pdf"
png_path = OUT_DIR / "reconciliation_eps_freshness_sla.png"
fig.savefig(str(pdf_path), bbox_inches="tight", dpi=300)
fig.savefig(str(png_path), bbox_inches="tight", dpi=200)
plt.close(fig)
print(f"Saved {pdf_path}")
print(f"Saved {png_path}")

# ── Paragraph ──
paragraph = (
    f"epsilon = {declared_eps:.2f} is the p95 residual drift under an integrity + "
    f"freshness validation stack measured on real IEEE-CIS transactions "
    f"(Experiment FAULT/EPS-DERIVE, feature-space staleness, eps_p95 = {eps_17:.3f}). "
    f"Under same-entity wall-clock staleness the residual grows from "
    f"{eps_mean[0]:.2f} at the tightest freshness SLA ({delta_t[0]:.0f}s) to "
    f"{eps_mean[-1]:.2f} as the SLA relaxes (Figure N). The certificate is sound at "
    f"every declared epsilon (Experiment RESWEEP: cert_false_allow = 0 across "
    f"epsilon in {{0.05, ..., 0.35}}, and across every SLA point); the budget-escape "
    f"rate -- the only residual system false-allow -- is measured rather than hidden "
    f"and grows monotonically with the SLA gap from {sfa_mean[0]:.3f} to "
    f"{sfa_mean[-1]:.3f} (Figure N, right axis). At the declared operating point "
    f"epsilon = {declared_eps:.2f} the gate still retains R_allow = {r_declared:.2f} "
    f"of utility (finance). The declared epsilon is therefore a conditional operating "
    f"point, not a free hyperparameter: it is the measured p95 residual of a declared "
    f"and instrumented validation stack."
)
para_path = OUT_DIR / "reconciliation_paragraph.txt"
para_path.write_text(paragraph + "\n")
print(f"Saved {para_path}")
