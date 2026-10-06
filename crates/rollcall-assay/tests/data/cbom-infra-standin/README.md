# cbom-infra stand-in catalogues (hand-written)

cbom-infra is not built yet, so these two files stand in for its copy of rollcall's algorithm
catalogue (`crates/rollcall-assay/db/algorithms.yaml`) in the tests of
`scripts/check-catalogue-sync.sh` (`crates/rollcall-assay/tests/catalogue_sync.rs`). They
are hand-written test data, not fixtures from a real build, so they live here and not under
`fixtures/`.

- `agrees.yaml`: a subset of rollcall's entries and parameter sets (AES-GCM, Ed25519, ML-KEM,
  SHA2/256 and SHA2/384) with every field equal except the prose `source`, plus one entry
  rollcall does not have (Camellia-CBC). The sync check passes.
- `disagrees.yaml`: `agrees.yaml` with two fields changed: AES-GCM/128
  `nist_quantum_security_level` 1 → 3 and ML-KEM `quantum_risk` pq-safe → grover-weakened.
  The sync check fails and names both.

If a shared entry of rollcall's catalogue changes, update `agrees.yaml` (and the same entry in
`disagrees.yaml`) to match, as cbom-infra would.
