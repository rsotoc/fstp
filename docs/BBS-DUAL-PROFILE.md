# BBS product path — IETF CFRG only

| Profile | Module | Agent routes | Status |
|---------|--------|--------------|--------|
| **IETF CFRG (default)** | `bbs_ietf` | `/fstp/crypto/bbs/ietf/*` | **Active** (zkryptium 0.6.2) |
| Ursa (legacy) | `bbs_plus` | `/fstp/crypto/bbs/*` | **410 Gone** — not a second product path |

- Ciphersuite: `BLS12-381-SHA-256` · draft-irtf-cfrg-bbs-signatures-10
- Status: `GET /fstp/crypto/bbs/ietf/status`
- Velyzor: `velizor.bbs.crypto-profile=BBS_IETF_CFRG`, `ursa-legacy-enabled=false`
- Holder: fstp proxy `/ietf/derive-proof` (Mattr WASM is Ursa-only; pairing_crypto later)
- Range proofs: [AGR-DT-RANGE-ZK](../../velizor-dev-docs/tickets/ssi/AGR-DT-RANGE-ZK.md)

```bash
cargo test -p fstp-core bbs_ietf::
```

Emergency rollback only: set `velizor.bbs.ursa-legacy-enabled=true` **and** restore Ursa handlers (currently Gone).
