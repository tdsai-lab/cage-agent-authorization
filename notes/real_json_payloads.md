# Realistic Structured JSON Payloads

## Purpose

AgentDojo strongly informs the **tool-identity channel `t`** and the **text/categorical channel
`x_1`**, and confirms by schema that numeric fields are common, but it does **not** give us
realistic *numeric distributions* for the **`x_2` channel** — every numeric field is flattened to
YAML text at the LLM boundary (see the paper's motivation section). This file collects
structured payloads that carry honest numeric fields, to seed the `x_2` channel of
`ToolDecisionBench`.

## Provenance — read this

**All payloads here are `synthetic_but_realistic`.** They are hand-drafted to mimic the *shape*
and *plausible ranges* of real API responses (vital-sign ranges, FICO bands, OFAC list names,
SEV levels, METAR-style weather fields). They are **not** captured from any live API, and the
specific values/entities are invented. The field names and units follow common conventions
(e.g. `mmHg`, `mg/dL`, `match_score in [0,1]`, `cpu_pct in [0,100]`) so the schema is faithful
even though the records are fabricated. Do not cite them as real-API data.

Machine-readable copies (one JSON object per line) live in
`bridge_benchmark/schemas/api_payload_examples.jsonl` — **16 records**:
6 medical, 6 finance/compliance, 3 system-monitoring, 1 weather (≥ the 5/5/3 minimum).

## Record shape

```json
{
  "domain": "financial_compliance",
  "tool_name": "sanctions_screen",
  "payload": { "entity_name": "ACME Trading Ltd.", "match_score": 0.87, "country": "XX",
  "list_type": "OFAC_SDN", "confidence": 0.92, "screened_at": "2026-01-01T00:00:00Z" },
  "candidate_action": "escalate",
  "text_fields": ["entity_name", "country", "list_type"],
  "numeric_fields": ["match_score", "confidence"],
  "provenance": "synthetic_but_realistic"
}
```

`text_fields` mark the `x_1` (discrete/categorical/text) channel; `numeric_fields` mark the `x_2`
(continuous) channel; `tool_name` is the `t` channel; `candidate_action` is a draft label `a`.

## Medical triage (6)

| tool | key numeric fields | text fields | candidate action |
|---|---|---|---|
| `blood_pressure` | systolic=142, diastolic=91 | unit, position, cuff_size | follow_up |
| `glucose` | value=142 (fasting) | unit, sample_type | urgent |
| `cholesterol` | total=268, ldl=190, hdl=38, trig=210 | unit | follow_up |
| `symptom_checker` | onset_hours=1, severity=8 (chest pain) | chief_complaint, risk_band | critical |
| `blood_pressure` | systolic=118, diastolic=76 | unit, position, cuff_size | normal |
| `symptom_checker` | onset_hours=48, severity=3 (sore throat) | chief_complaint, risk_band | normal |

Note the **interaction**: the value `142` means `follow_up` from `blood_pressure` (systolic) but
`urgent` from `glucose` (fasting mg/dL). Same number, different tool, different action. This seeds
the interaction-only examples in `notes/benchmark_spec.md`.

## Finance / compliance (6)

| tool | key numeric fields | text fields | candidate action |
|---|---|---|---|
| `sanctions_screen` | match_score=0.87, confidence=0.92 | entity_name, country=XX, list_type | escalate |
| `credit_check` | score=612, utilization=0.74, delinq=2 | applicant_id, model=FICO-9 | flag |
| `transaction_monitor` | amount=9800, risk_score=0.81, structuring=true | currency, channel=wire, ctpy_country=KY | reject |
| `transaction_monitor` | amount=42.5, risk_score=0.06 | currency, channel=card, ctpy_country=US | approve |
| `sanctions_screen` | match_score=0.12, confidence=0.97 | entity_name, country=US, list_type | approve |
| `market_data` | last_price=14.2, intraday_change=-23.5%, halt | symbol, venue=NASDAQ | escalate |

Note the **near-threshold structuring** case: `amount=9800` (just under a 10k reporting line) +
`structuring_flag` is what flips `transaction_monitor` from `approve` to `reject` — an
`epsilon`-sensitive boundary that motivates the continuous certificate.

## System / weather monitoring (4)

| tool | key numeric fields | text fields | candidate action |
|---|---|---|---|
| `cpu_monitor` | cpu_pct=96.4, load_1m=14.2, cores=8 | host, region | alert |
| `latency_monitor` | p99_ms=1840, error_rate=0.07 | service, window | page_human |
| `incident_detector` | anomaly_score=0.93, duration_min=12 | signal, severity=SEV2 | page_human |
| `weather_alert` | wind_gust_kt=48, visibility_mi=0.5 | station, condition=fog, alert_level | watch |

## How these map to the three benchmark domains

These payloads are deliberately drawn from the same three domains as `ToolDecisionBench`
(medical triage, financial compliance, system monitoring; weather is folded into monitoring),
so they can be lifted directly into the canonical record format in `notes/benchmark_spec.md`
(`text_fields` -> `x_1`, `numeric_fields` -> `x_2`, `tool_name` -> `tool_id`,
`candidate_action` -> `action_label`).
