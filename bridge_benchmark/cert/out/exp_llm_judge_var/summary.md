# T1-4 — LLM-judge baselines (the non-guarantee, measured)

- config: {"n_c": 12, "n_r": 8, "n_W": 12, "n_total": 20, "model": "qwen2.5:7b-instruct", "guard_model": "llama-guard3:1b", "prompt_variants": 3, "seeds": [0, 1, 2], "eps": 0.1, "threat_temperature": 0.7, "endpoint": "http://localhost:11434", "llm_available": true, "llm_reason": "reachable"}

| judge_stage | variant | allow_on_W | cert_FA | notes |
|---|---|---|---|---|
| certified_gate_reference | - | 0.000 | 0.000 | sound (certified gate), not an LLM |
| point | canonical | 0.917 | 0.550 | cannot see the ball |
| threat_aware | AGG (3ph x 3seed) | 0.444 +/- 0.429 (min 0.000, max 1.000) | 0.267 +/- 0.257 (min 0.000, max 0.600) | measured non-guarantee: variance across phrasings/seeds |
| guard | llama-guard3:1b | 0.500 | 0.300 | deployed guard model |
