# NEW_MCP_EXP Stage 0 — typed-return substrate scan (static, zero execution)

Frozen detector `221aa906dca8a79e`. Corpus: MCP reference servers @`b2a94a21a53f` (7 servers, 43 tools, parse_coverage 1.0).

**substrate_rate = 0.0** (0/43). typed-return=14, untyped-return=29; of typed: continuous_x=1, pipeline_set_s=0, both(substrate)=0.

**Outcome: NULL_no_typed_return_substrate** — funnel null located at: substrate stage (typed-return): returns are untyped or carry no pipeline-set provenance alongside a continuous field

### Typed-return inventory (every tool with an outputSchema)

- `everything/get-structured-content` → temperature:number→continuous_x, conditions:string→other, humidity:number→continuous_x
- `filesystem/read_file` → content:string→other
- `filesystem/read_text_file` → content:string→other
- `filesystem/read_multiple_files` → content:string→other
- `filesystem/write_file` → content:string→other
- `filesystem/edit_file` → content:string→other
- `filesystem/create_directory` → content:string→other
- `filesystem/list_directory` → content:string→other
- `filesystem/list_directory_with_sizes` → content:string→other
- `filesystem/directory_tree` → content:string→other
- `filesystem/move_file` → content:string→other
- `filesystem/search_files` → content:string→other
- `filesystem/get_file_info` → content:string→other
- `filesystem/list_allowed_directories` → content:string→other

**Read.** MCP tool returns are predominantly untyped or, where typed, carry a bare `content:string` or a continuous-only structured demo return — none pair a continuous operational field with a PIPELINE-SET provenance field. The `z=(s,x)` substrate with pipeline-set `s` does not appear in the typed returns of the public reference corpus. This localizes the data-half null at the substrate stage, complementary to the §6.5 policy-half k8s/cloud null. (See limitation: static parse, reference corpus; live introspection of the broader third-party set declined for a bonus experiment whose null is the expected outcome.)
