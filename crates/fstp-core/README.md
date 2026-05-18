# fstp-core

Protocol primitives for the **Federated Sovereign Transport Protocol (FSTP)**:

- **Synchronization Agent** — closed `FstpMessage` output enumeration (synchronization confinement)
- **Contextual identity** — HKDF-derived CIIs, unlinkable across federation links
- **Blocklace** — tamper-evident DAG with O(Δ) sync and erasure-safe dangling pointers

## Usage

```toml
[dependencies]
fstp-core = "0.1"
# or from git until crates.io publish:
# fstp-core = { git = "https://github.com/rsotoc/fstp", tag = "v0.1.0" }
```

## Auditing

Before federating with a peer, review `src/message.rs` and the git tag you deploy. See the [repository CONTRIBUTING guide](https://github.com/rsotoc/fstp/blob/main/CONTRIBUTING.md).

## License

Apache-2.0
