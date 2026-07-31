# T1-4 — LLM-judge baselines (the non-guarantee, measured)

- config: {"n_c": 120, "n_r": 120, "n_W": 120, "n_total": 240, "model": "qwen3.6", "guard_model": "llama-guard3:1b", "prompt_variants": 4, "seeds": [0, 1, 2], "eps": 0.1, "threat_temperature": 0.0, "endpoint": "http://localhost:11434", "llm_available": true, "llm_reason": "reachable"}

| judge_stage | variant | allow_on_W | cert_FA | notes |
|---|---|---|---|---|
| certified_gate_reference | - | 0.000 | 0.000 | sound (certified gate), not an LLM |
| point | canonical | 0.258 | 0.129 | cannot see the ball |
| threat_aware | AGG (4ph x 3seed) | 0.154 +/- 0.267 (min 0.000, max 0.617) | 0.077 +/- 0.134 (min 0.000, max 0.308) | measured non-guarantee: variance across phrasings/seeds |
| guard | llama-guard3:1b | 0.400 | 0.200 | deployed guard model |
