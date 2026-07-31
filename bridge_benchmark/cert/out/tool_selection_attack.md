# IDEA #3 — tool-selection poisoning as a controlled limit

ε=0.1, multi-action-group tool table (K=12, k=4). The certified node is `Allow(z,a)` **after** the tool returns, per action; it does NOT certify tool selection. An attacker poisons tool metadata so the top-1 selector picks the WRONG tool; we measure `P[unsafe execution | dangerous transaction mis-selected]` with no gate vs the certified robust-oracle gate.

| regime | retrieval ASR | n | P[unsafe] no-gate | **P[unsafe] certified** | cert-allow |
|---|---:|---:|---:|---:|---:|
| within_group | 1.0 | 1816 | 1.0 | **0.0** | 0.0 |
| cross_action | 1.0 | 1816 | 1.0 | **0.3117** | 0.3117 |

**Reads.** Metadata poisoning flips selection (ASR≈1.0). `within_group` mis-selection (a provenance swap to another tool sharing the gated action) puts the correct tool inside the gate's `B_{1,ε}` ball → the gate's worst-over-neighbours reasoning **covers** it and drives `P[unsafe]→0`: the certified node incidentally neutralises in-budget (single-provenance) mis-selection. `cross_action` mis-selection (to a tool bound to a DIFFERENT action) puts the correct tool outside the per-action ball → the gate certifies the wrong action and **residual harm survives** (P[unsafe]>0). Exactly the intended limit: **the gate does not certify selection**, but blocks the mis-selections whose provenance error is in its typed per-action budget; a selection error that crosses the action boundary is out of scope and the gate is honestly silent. Tool retrieval/selection remains a separate upstream defense surface (coheres with P2's breaking radius).
