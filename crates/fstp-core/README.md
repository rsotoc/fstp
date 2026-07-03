# fstp-core

**Verifiable coordination without disclosure.**

Protocol primitives for the [Federated Sovereign Transport Protocol (FSTP)](https://github.com/rsotoc/fstp):

| Primitive | Module | Role |
|-----------|--------|------|
| **Synchronization Agent** | `message`, `sa_machine` | Closed `FstpMessage` output enum — compile-time confinement |
| **Contextual identity** | `identity` | HKDF-derived CIIs, unlinkable across federation links |
| **Blocklace** | `blocklace` | Tamper-evident DAG; O(Δ) sync; erasure-safe dangling pointers |

## Quick start

```toml
[dependencies]
fstp-core = "0.1"
```

```bash
cargo run --example two_nodes -p fstp-core
```

The `two_nodes` example runs a full Blocklace sync round with no HTTP, TLS, or network stack.

## Auditing the confinement boundary

Before federating with a peer, review [`src/message.rs`](src/message.rs) at the git tag you deploy. If `FstpMessage` has no `D_raw` fields and the crate compiles, confinement holds for all executions (see [arXiv:2607.00213](https://arxiv.org/abs/2607.00213), §3.1).

Full audit procedure: [CONTRIBUTING.md](https://github.com/rsotoc/fstp/blob/main/CONTRIBUTING.md).

## API stability

`0.1.x` tracks the protocol described in the FSTP paper. Minor releases may extend `FstpMessage` variants; patch releases are bug fixes only.

## License

Apache-2.0 — see [LICENSE](LICENSE).
