# CX5 policy bundle — PROVENANCE (freeze-first)

- **Source:** github.com/openfisca/openfisca-france (OpenFisca-France), Bail Réel Solidaire income ceilings.
- **Commit (frozen):** `a9d8dcbe900e26932ec557a4a9ae7869f7a10c62`
- **Path:** `external/corpora/openfisca_openfisca-france/openfisca_france/parameters/prestations_sociales/bail_reel_solidaire/plafonds_par_zones`
- **Parameter year:** 2025-01-01
- **Legal references:** Article R255-1 CCH, Arrêté du 11/12/2023, Annexe
- **Rule NOT modified.** Only a documented schema mapping: s = zone (categorical), x = resources/€120598 (normalized), θ(zone,size) = the real ceiling.
- **s semantics:** zone = subject/region categorical (not pipeline-provenance) — deployed-threshold existence anchor per the claim ladder.
