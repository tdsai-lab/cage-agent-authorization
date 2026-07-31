# NEW_EXPS T2-6 — MCP registry-scale typed-return substrate scan (zero execution)

Frozen detector `221aa906dca8a79e` (identical to the reference-server scan). Corpus: third-party MCP registries: smithery, glama. Execution: none (zero-execution: published registry-API tool schemas parsed as JSON; no server installed / npx'd / run — that is the declined introspect.py path)

**substrate_rate = 0.049839** over 622 typed returns (Wilson 95% CI (0.035331, 0.069874)); 0.006198 over all 5002 tools (Wilson 95% CI (0.00437, 0.008783)).

### Funnel

| stage | count |
|---|---|
| servers scanned | 1085 |
| tools | 5002 |
| typed returns (outputSchema w/ properties) | 622 (coverage 0.1244) |
| typed w/ continuous_x | 147 |
| typed w/ pipeline_set_s | 70 |
| substrate (both, frozen detector) | 31 |

### Per-registry

| registry | servers (scanned/avail) | tools | typed | cont_x | pipe_s | substrate |
|---|---|---|---|---|---|---|
| smithery | 285/6662 | 5002 | 622 | 147 | 70 | 31 |
| glama | 800/? | 0 | 0 | 0 | 0 | 0 |

**Outcome: SUBSTRATE_PRESENT_candidate_hits** — funnel null located at: n/a — candidate substrate present; adjudicate (Stage 2)

Fetch: net=78 cache=220 fail=0 (offline=False).

**Note.** Smithery serves real inputSchema/outputSchema per tool; a bare {'type':'object'} outputSchema with no properties is UNTYPED (the reference-corpus mode) and cannot be substrate. Glama's public API serves no tool schemas -> its servers are recorded typed_return=absent (honest; never inflates substrate). Any hit is a CANDIDATE from the frozen automated detector and would need Stage-2 manual adjudication (pipeline-set vs subject-keyed), exactly as in openapi_adjudicate.py.

**Limitation.** Zero-execution: we parse published schemas, not runtime returns; dynamically-built outputSchemas and servers whose registry omits an outputSchema are undercounted (an honest undercount of typed returns, logged as coverage — never inflates substrate). Smithery paginates with a page cap; the cap and total-available are logged. Glama contributes counts only. Live third-party introspection remains DECLINED (supply-chain risk > bonus-experiment upside).
