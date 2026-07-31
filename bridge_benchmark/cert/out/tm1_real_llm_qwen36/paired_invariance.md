# TM1 paired invariance — vary only the display text m for each fixed typed return z

`LLMFlip(z)`=1 if the LLM proposal changes across display attacks; `GateFlip(z)`=1 if the gate ALLOW decision changes. A typed gate receives only z, so `gate_flip_rate = 0` by construction (non-instructability), while the LLM is instructable (`llm_flip_rate > 0`).

| model | prompt_mode | gate | domain | n_paired_z | llm_flip_rate | gate_flip_rate | exec_flip_rate | priv_prop_spread_paired | unsafe_exec_spread_paired |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| qwen3.6 | policy_explicit | none | finance | 60 | 0.250 | 0.000 | 0.250 | 0.250 | 0.000 |
| qwen3.6 | policy_explicit | certified | finance | 60 | 0.250 | 0.000 | 0.083 | 0.250 | 0.000 |
| qwen3.6 | robust | none | finance | 180 | 0.650 | 0.000 | 0.344 | 0.344 | 0.006 |
| qwen3.6 | standard | none | finance | 60 | 0.833 | 0.000 | 0.800 | 0.800 | 0.300 |
| qwen3.6 | standard | rule | finance | 60 | 0.833 | 0.000 | 0.500 | 0.800 | 0.000 |
| qwen3.6 | standard | learned | finance | 60 | 0.833 | 0.000 | 0.500 | 0.800 | 0.000 |
| qwen3.6 | standard | certified | finance | 60 | 0.833 | 0.000 | 0.067 | 0.800 | 0.000 |
| qwen3.6 | policy_explicit | none | sre | 60 | 0.233 | 0.000 | 0.233 | 0.233 | 0.017 |
| qwen3.6 | policy_explicit | certified | sre | 60 | 0.233 | 0.000 | 0.083 | 0.233 | 0.000 |
| qwen3.6 | robust | none | sre | 180 | 0.933 | 0.000 | 0.933 | 0.933 | 0.322 |
| qwen3.6 | standard | none | sre | 60 | 0.800 | 0.000 | 0.800 | 0.800 | 0.317 |
| qwen3.6 | standard | rule | sre | 60 | 0.800 | 0.000 | 0.483 | 0.800 | 0.000 |
| qwen3.6 | standard | learned | sre | 60 | 0.800 | 0.000 | 0.483 | 0.800 | 0.000 |
| qwen3.6 | standard | certified | sre | 60 | 0.800 | 0.000 | 0.033 | 0.800 | 0.000 |

**Reading.** m moves the LLM policy (`llm_flip_rate` > 0) but not the typed authorization gate (`gate_flip_rate` = 0). This is non-instructability by construction, not prompt-injection detection.
