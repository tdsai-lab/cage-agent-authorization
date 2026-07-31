# M1 — Wilson-95% upper bounds + explicit n/N for every zero cell

every quoted zero now carries a numerator, a denominator, and a Wilson-95% upper bound, with the denominator semantics stated so the four denominators cannot be conflated. `cp95_upper` = exact Clopper-Pearson cross-check.

**71 zero cells audited.** All k=0 except where noted; no result value changes (this is post-processing).

| table | setting | metric | k/N | Wilson-95% upper | CP-95% upper | denominator | evidence |
|---|---|---|---|---|---|---|---|
| T4/T5-syn | synthetic canonical (enumerate+RS gate) | `cert_false_allow` | 0/24 | 0.138 | 0.1425 | N = certified-allow decisions; k = oracle-unsafe among them | per_example |
| T4/T5-syn | synthetic canonical (enumerate+RS gate) | `C_allow` | 0/40 | 0.08762 | 0.0881 | N = Category-C records; k = of them the gate allowed | per_example |
| T4/T5-syn | synthetic canonical (enumerate+RS gate) | `U_allow` | 0/40 | 0.08762 | 0.0881 | N = Category-U records; k = of them the gate allowed | per_example |
| T5-REG | REG psd2_low_value/natural/eps=0.03 | `C_allow` | 0/11 | 0.2588 | 0.2849 | N = Category-C records (engine-labeled) | summary_recorded_N |
| T5-REG | REG psd2_low_value/natural/eps=0.03 | `U_allow` | 0/149 | 0.02513 | 0.02445 | N = Category-U records = round(U_pct*n) | summary_recorded_N |
| T5-REG | REG psd2_low_value/natural/eps=0.03 | `cert_false_allow` | 0/70 | 0.05202 | 0.05133 | N = certified-allow decisions = round(R_allow*R_count) | summary_recorded_N |
| T5-REG | REG psd2_low_value/natural/eps=0.1 | `C_allow` | 0/39 | 0.08967 | 0.09025 | N = Category-C records (engine-labeled) | summary_recorded_N |
| T5-REG | REG psd2_low_value/natural/eps=0.1 | `U_allow` | 0/149 | 0.02513 | 0.02445 | N = Category-U records = round(U_pct*n) | summary_recorded_N |
| T5-REG | REG psd2_low_value/natural/eps=0.1 | `cert_false_allow` | 0/35 | 0.0989 | 0.1 | N = certified-allow decisions = round(R_allow*R_count) | summary_recorded_N |
| T5-REG | REG psd2_low_value/boundary/eps=0.03 | `C_allow` | 0/14 | 0.2153 | 0.2316 | N = Category-C records (engine-labeled) | summary_recorded_N |
| T5-REG | REG psd2_low_value/boundary/eps=0.03 | `U_allow` | 0/213 | 0.01772 | 0.01717 | N = Category-U records = round(U_pct*n) | summary_recorded_N |
| T5-REG | REG psd2_low_value/boundary/eps=0.1 | `C_allow` | 0/44 | 0.0803 | 0.08042 | N = Category-C records (engine-labeled) | summary_recorded_N |
| T5-REG | REG psd2_low_value/boundary/eps=0.1 | `U_allow` | 0/213 | 0.01772 | 0.01717 | N = Category-U records = round(U_pct*n) | summary_recorded_N |
| T5-REG | REG psd2_tra/natural/eps=0.03 | `C_allow` | 0/17 | 0.1843 | 0.1951 | N = Category-C records (engine-labeled) | summary_recorded_N |
| T5-REG | REG psd2_tra/natural/eps=0.03 | `U_allow` | 0/221 | 0.01708 | 0.01655 | N = Category-U records = round(U_pct*n) | summary_recorded_N |
| T5-REG | REG psd2_tra/natural/eps=0.03 | `cert_false_allow` | 0/28 | 0.1206 | 0.1234 | N = certified-allow decisions = round(R_allow*R_count) | summary_recorded_N |
| T5-REG | REG psd2_tra/natural/eps=0.1 | `C_allow` | 0/32 | 0.1072 | 0.1089 | N = Category-C records (engine-labeled) | summary_recorded_N |
| T5-REG | REG psd2_tra/natural/eps=0.1 | `U_allow` | 0/221 | 0.01708 | 0.01655 | N = Category-U records = round(U_pct*n) | summary_recorded_N |
| T5-REG | REG psd2_tra/natural/eps=0.1 | `cert_false_allow` | 0/8 | 0.3244 | 0.3694 | N = certified-allow decisions = round(R_allow*R_count) | summary_recorded_N |
| T5-REG | REG psd2_tra/boundary/eps=0.03 | `C_allow` | 0/18 | 0.1759 | 0.1853 | N = Category-C records (engine-labeled) | summary_recorded_N |
| T5-REG | REG psd2_tra/boundary/eps=0.03 | `U_allow` | 0/201 | 0.01875 | 0.01818 | N = Category-U records = round(U_pct*n) | summary_recorded_N |
| T5-REG | REG psd2_tra/boundary/eps=0.1 | `C_allow` | 0/43 | 0.08201 | 0.08221 | N = Category-C records (engine-labeled) | summary_recorded_N |
| T5-REG | REG psd2_tra/boundary/eps=0.1 | `U_allow` | 0/201 | 0.01875 | 0.01818 | N = Category-U records = round(U_pct*n) | summary_recorded_N |
| T5-REG | REG aml_ctr/natural/eps=0.03 | `C_allow` | 0/9 | 0.2991 | 0.3363 | N = Category-C records (engine-labeled) | summary_recorded_N |
| T5-REG | REG aml_ctr/natural/eps=0.03 | `U_allow` | 0/208 | 0.01813 | 0.01758 | N = Category-U records = round(U_pct*n) | summary_recorded_N |
| T5-REG | REG aml_ctr/natural/eps=0.03 | `cert_false_allow` | 0/76 | 0.04811 | 0.04738 | N = certified-allow decisions = round(R_allow*R_count) | summary_recorded_N |
| T5-REG | REG aml_ctr/natural/eps=0.1 | `C_allow` | 0/26 | 0.1287 | 0.1323 | N = Category-C records (engine-labeled) | summary_recorded_N |
| T5-REG | REG aml_ctr/natural/eps=0.1 | `U_allow` | 0/208 | 0.01813 | 0.01758 | N = Category-U records = round(U_pct*n) | summary_recorded_N |
| T5-REG | REG aml_ctr/natural/eps=0.1 | `cert_false_allow` | 0/37 | 0.09406 | 0.09489 | N = certified-allow decisions = round(R_allow*R_count) | summary_recorded_N |
| T5-REG | REG aml_ctr/boundary/eps=0.03 | `C_allow` | 0/15 | 0.2039 | 0.218 | N = Category-C records (engine-labeled) | summary_recorded_N |
| T5-REG | REG aml_ctr/boundary/eps=0.03 | `U_allow` | 0/205 | 0.01839 | 0.01783 | N = Category-U records = round(U_pct*n) | summary_recorded_N |
| T5-REG | REG aml_ctr/boundary/eps=0.1 | `C_allow` | 0/61 | 0.05924 | 0.05868 | N = Category-C records (engine-labeled) | summary_recorded_N |
| T5-REG | REG aml_ctr/boundary/eps=0.1 | `U_allow` | 0/205 | 0.01839 | 0.01783 | N = Category-U records = round(U_pct*n) | summary_recorded_N |
| T5/S14-NAB | NAB (real EC2/RDS CPU) / backend=lip | `C_allow` | 0/1964 | 0.001952 | 0.001876 | N = Category-C records over 3 seeds | summary_recorded_N |
| T5/S14-NAB | NAB (real EC2/RDS CPU) / backend=lip | `U_allow` | 0/4000 | 0.000959 | 0.000922 | N = Category-U records over 3 seeds | summary_recorded_N |
| T5/S14-NAB | NAB (real EC2/RDS CPU) / backend=lip | `cert_false_allow` | 0/8296 | 0.000463 | 0.000445 | N = certified-allow decisions over 3 seeds = sum round(R_allow*R_count) | summary_recorded_N |
| T5/S14-NAB | NAB (real EC2/RDS CPU) / backend=rs | `C_allow` | 0/1964 | 0.001952 | 0.001876 | N = Category-C records over 3 seeds | summary_recorded_N |
| T5/S14-NAB | NAB (real EC2/RDS CPU) / backend=rs | `U_allow` | 0/4000 | 0.000959 | 0.000922 | N = Category-U records over 3 seeds | summary_recorded_N |
| T5/S14-NAB | NAB (real EC2/RDS CPU) / backend=rs | `cert_false_allow` | 0/8296 | 0.000463 | 0.000445 | N = certified-allow decisions over 3 seeds = sum round(R_allow*R_count) | summary_recorded_N |
| T5/S14-NAB | NAB (real EC2/RDS CPU) / backend=exact | `C_allow` | 0/1964 | 0.001952 | 0.001876 | N = Category-C records over 3 seeds | summary_recorded_N |
| T5/S14-NAB | NAB (real EC2/RDS CPU) / backend=exact | `U_allow` | 0/4000 | 0.000959 | 0.000922 | N = Category-U records over 3 seeds | summary_recorded_N |
| T5/S14-NAB | NAB (real EC2/RDS CPU) / backend=exact | `cert_false_allow` | 0/8296 | 0.000463 | 0.000445 | N = certified-allow decisions over 3 seeds = sum round(R_allow*R_count) | summary_recorded_N |
| T4-OPA | OPA-TrackC finance/lipschitz (eps=0.1,tau=0.9) | `C_allow` | 0/108 | 0.03435 | 0.03358 | N = Category-C records (OPA-labeled) over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC finance/lipschitz (eps=0.1,tau=0.9) | `U_allow` | 0/311 | 0.0122 | 0.01179 | N = Category-U records (OPA-labeled) over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC finance/lipschitz (eps=0.1,tau=0.9) | `cert_false_allow` | 0/111 | 0.03345 | 0.03269 | N = certified-allow decisions over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC finance/smoothing (eps=0.1,tau=0.9) | `C_allow` | 0/108 | 0.03435 | 0.03358 | N = Category-C records (OPA-labeled) over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC finance/smoothing (eps=0.1,tau=0.9) | `U_allow` | 0/311 | 0.0122 | 0.01179 | N = Category-U records (OPA-labeled) over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC finance/smoothing (eps=0.1,tau=0.9) | `cert_false_allow` | 0/21 | 0.1546 | 0.1611 | N = certified-allow decisions over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC ops/lipschitz (eps=0.1,tau=0.9) | `C_allow` | 0/108 | 0.03435 | 0.03358 | N = Category-C records (OPA-labeled) over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC ops/lipschitz (eps=0.1,tau=0.9) | `U_allow` | 0/311 | 0.0122 | 0.01179 | N = Category-U records (OPA-labeled) over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC ops/lipschitz (eps=0.1,tau=0.9) | `cert_false_allow` | 0/121 | 0.03077 | 0.03003 | N = certified-allow decisions over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC ops/smoothing (eps=0.1,tau=0.9) | `C_allow` | 0/108 | 0.03435 | 0.03358 | N = Category-C records (OPA-labeled) over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC ops/smoothing (eps=0.1,tau=0.9) | `U_allow` | 0/311 | 0.0122 | 0.01179 | N = Category-U records (OPA-labeled) over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC ops/smoothing (eps=0.1,tau=0.9) | `cert_false_allow` | 0/22 | 0.1487 | 0.1544 | N = certified-allow decisions over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC sre/lipschitz (eps=0.1,tau=0.9) | `C_allow` | 0/108 | 0.03435 | 0.03358 | N = Category-C records (OPA-labeled) over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC sre/lipschitz (eps=0.1,tau=0.9) | `U_allow` | 0/311 | 0.0122 | 0.01179 | N = Category-U records (OPA-labeled) over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC sre/lipschitz (eps=0.1,tau=0.9) | `cert_false_allow` | 0/123 | 0.03029 | 0.02955 | N = certified-allow decisions over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC sre/smoothing (eps=0.1,tau=0.9) | `C_allow` | 0/108 | 0.03435 | 0.03358 | N = Category-C records (OPA-labeled) over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC sre/smoothing (eps=0.1,tau=0.9) | `U_allow` | 0/311 | 0.0122 | 0.01179 | N = Category-U records (OPA-labeled) over 3 seeds | summary_recorded_N |
| T4-OPA | OPA-TrackC sre/smoothing (eps=0.1,tau=0.9) | `cert_false_allow` | 0/14 | 0.2153 | 0.2316 | N = certified-allow decisions over 3 seeds | summary_recorded_N |
| S20/S22 | realistic-schema finance_compliance | `C_allow` | 0/4050 | 0.000948 | 0.00091 | N = Category-C records | summary_recorded_N |
| S20/S22 | realistic-schema finance_compliance | `U_allow` | 0/17200 | 0.000223 | 0.000214 | N = Category-U records | summary_recorded_N |
| S20/S22 | realistic-schema finance_compliance | `cert_false_allow` | 0/3952 | 0.000971 | 0.000933 | N = certified-allow decisions = round(R_allow*R_count) | summary_recorded_N |
| S20/S22 | realistic-schema sre_monitoring | `C_allow` | 0/4000 | 0.000959 | 0.000922 | N = Category-C records | summary_recorded_N |
| S20/S22 | realistic-schema sre_monitoring | `U_allow` | 0/15600 | 0.000246 | 0.000236 | N = Category-U records | summary_recorded_N |
| S20/S22 | realistic-schema sre_monitoring | `cert_false_allow` | 0/840 | 0.004552 | 0.004382 | N = certified-allow decisions = round(R_allow*R_count) | summary_recorded_N |
| S20/S22 | realistic-schema ops_security | `C_allow` | 0/4300 | 0.000893 | 0.000858 | N = Category-C records | summary_recorded_N |
| S20/S22 | realistic-schema ops_security | `U_allow` | 0/16150 | 0.000238 | 0.000228 | N = Category-U records | summary_recorded_N |
| S20/S22 | realistic-schema ops_security | `cert_false_allow` | 0/1104 | 0.003468 | 0.003336 | N = certified-allow decisions = round(R_allow*R_count) | summary_recorded_N |
| T2-EXP1 | EXP1 exact_rung1 (explicit × neighborhood) | `attack_false_allow` | 0/6032 | 0.000636 | 0.000611 | N = in-budget exploit witnesses W (mean 6032/10000 over 5 seeds) | summary_recorded_N |
| T2-EXP1 | EXP1 certified_rs (implicit × neighborhood) | `attack_false_allow` | 0/6032 | 0.000636 | 0.000611 | N = in-budget exploit witnesses W (mean 6032/10000 over 5 seeds) | summary_recorded_N |

**Range.** Tightest zero-cell bound: `U_allow` at realistic-schema finance_compliance — Wilson-95% upper 0.000223 (N=17200). Loosest: `cert_false_allow` at REG psd2_tra/natural/eps=0.1 — Wilson-95% upper 0.3244 (N=8).
