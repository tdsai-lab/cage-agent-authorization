# A8 — external-harness flagship: the certified node is harness-agnostic

Second real MCP server **secure-filesystem-server 0.2.0** (@modelcontextprotocol/server-filesystem), heterogeneous to `kubernetes-mcp-server` (P3-MCP). Same provenance-conditioned gate: export size ≤ quota(tier), quotas {'strict': 1.0, 'lax': 2.0} MB, ε=0.1; served (stale) tier=lax, true=strict. Server write tools: `['write_file', 'edit_file', 'create_directory', 'move_file']`.

| arm | requested | file written | file size | **unsafe side effect** |
|---|---:|:--:|---:|:--:|
| no_gate | 1.5 MB | yes | 1.5 MB | **YES** |
| certified_gate | 1.5 MB | no | 0.0 MB | none |
| certified_gate (safe, non-vacuity) | 0.5 MB | yes | 0.5 MB | none |

**Reads.** The certified typed gate drops, unchanged, in front of a **second, heterogeneous real MCP server**: the deployed path commits a real over-quota file write (the side effect is a file on disk); the certified rung-1 gate — enumerating the tier neighbourhood and testing the ε-shifted quota — **blocks the write before the MCP call** while still allowing a genuinely-safe write (non-vacuous). Together with P3-MCP (kubernetes-mcp-server admission) and the Marble/Kyverno engines, the certified node mediates **heterogeneous real tool surfaces with one logic** — the external harness is not special. This is the flagship consolidation: real agent harness × real MCP servers × real side effects × a harness-agnostic certified gate.
