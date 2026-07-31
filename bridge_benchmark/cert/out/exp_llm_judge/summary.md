# T1-4 — LLM-judge baselines (the non-guarantee, measured)

- config: {"n_c": 20, "n_r": 20, "n_W": 20, "n_total": 40, "model": "qwen2.5:7b-instruct", "guard_model": "llama-guard3:1b", "prompt_variants": 2, "seeds": [0], "eps": 0.1, "threat_temperature": 0.7, "endpoint": "http://localhost:11434", "llm_available": true, "llm_reason": "reachable"}

| judge_stage | variant | allow_on_W | cert_FA | notes |
|---|---|---|---|---|
| certified_gate_reference | - | 0.000 | 0.000 | sound (certified gate), not an LLM |
| point | canonical | 0.900 | 0.450 | cannot see the ball |
| threat_aware | AGG (2ph x 1seed) | 0.050 +/- 0.050 (min 0.000, max 0.100) | 0.025 +/- 0.025 (min 0.000, max 0.050) | measured non-guarantee: variance across phrasings/seeds |
| guard | llama-guard3:1b | 0.450 | 0.225 | deployed guard model |
