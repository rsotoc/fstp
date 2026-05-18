# Contributing to FSTP

## Auditing the confinement boundary

The central security claim of FSTP (§3.1, §6 of the paper) is that no D_raw value can appear in any federation message. This guarantee rests on the Rust type system: if the program compiles, the property holds for all possible executions.

**The auditable artifact is `crates/fstp-core/src/message.rs`.**

To verify the guarantee before establishing a federation relationship with a node:

```bash
# 1. Clone the repository
git clone https://github.com/rsotoc/fstp
cd fstp

# 2. Inspect the closed output enumeration
cat crates/fstp-core/src/message.rs

# Verify that:
# - FstpMessage has exactly 4 variants (Table 2 of the paper)
# - No variant has a field that could carry raw content
#   (member records, deliberation text, vote data, etc.)
# - D_raw types are not imported in this file

# 3. Compile and run the test suite
cargo test -p fstp-core

# 4. Check the SA version declared in the peer's DID document
# and compare it against the git tag you reviewed
```

## Extending the output vocabulary

Deploying networks may add message types provided all additions satisfy Property 2.1 (no D_raw values). To add a variant:

1. Add it to `FstpMessage` in `crates/fstp-core/src/message.rs`
2. Update `type_name()` and `emitter_cii()` match arms
3. Update the `variant_count_matches_table_2` test to reflect the new count
4. Document the new type in the module-level doc comment
5. Open a pull request — the change is visible and auditable to any peer

Platform-specific extensions (e.g. credit transactions in Ágora) belong in the platform crate, not in `fstp-core`. See `crates/fstp-agent` for an example of how to build on top of `fstp-core` without modifying the core enum.

## Running tests

```bash
cargo test --workspace          # all tests
cargo test -p fstp-core         # protocol unit tests only
cargo test -p fstp-agent        # agent integration tests
cargo bench -p fstp-core        # Criterion benchmarks
cargo run --example two_nodes -p fstp-core  # protocol demo
```

## Code style

- No `unsafe` blocks in `fstp-core`
- D_raw types must not be importable in `message.rs` or `sa_machine.rs`
- Every outbound path through the SA must pass through `SaTransaction<Logging>`
- Audit records must never contain content fields (see `audit.rs`)

## Reporting security issues

Please report security issues privately before disclosing publicly. See [SECURITY.md](SECURITY.md).
