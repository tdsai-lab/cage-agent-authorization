# T1-4 — LLM-judge baselines (the non-guarantee, measured)

- config: {"n_c": 60, "n_r": 30, "n_W": 60, "n_total": 90, "model": "qwen2.5:32b", "guard_model": "llama-guard3:1b", "prompt_variants": 2, "seeds": [0, 1], "eps": 0.1, "threat_temperature": 0.0, "endpoint": "http://localhost:11434", "llm_available": true, "llm_reason": "reachable"}

| judge_stage | variant | allow_on_W | cert_FA | notes |
|---|---|---|---|---|
| certified_gate_reference | - | 0.000 | 0.000 | sound (certified gate), not an LLM |
| point | canonical | 0.133 | 0.089 | cannot see the ball |
| threat_aware | AGG (2ph x 2seed) | 0.000 +/- 0.000 (min 0.000, max 0.000) | 0.000 +/- 0.000 (min 0.000, max 0.000) | measured non-guarantee: variance across phrasings/seeds |
| guard | llama-guard3:1b | 0.417 | 0.278 | deployed guard model |
