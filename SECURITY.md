# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| `0.1.x` | Yes (active development) |

## Reporting a vulnerability

FSTP's central security claim is **synchronization confinement**: federation messages must not carry raw internal data (`D_raw`). If you believe you have found a way to bypass that guarantee, or any other security issue in `fstp-core` or `fstp-agent`, please report it **privately** before public disclosure.

1. **Do not** open a public GitHub issue for exploitable findings.
2. Use [GitHub private vulnerability reporting](https://github.com/rsotoc/fstp/security/advisories/new) for this repository (preferred), or email the maintainers if the repo is not yet created.
3. Include: affected crate/version, reproduction steps, impact assessment, and suggested fix if any.

We aim to acknowledge reports within **5 business days** and provide a remediation timeline when confirmed.

## What we consider in scope

- Bypass of the closed `FstpMessage` output enumeration (`crates/fstp-core/src/message.rs`)
- Leakage of `D_raw` through audit logs, HTTP/gRPC handlers, or Blocklace exports
- Cryptographic weaknesses in CII derivation, frontier signing, or mTLS configuration defaults
- Authentication/authorization flaws on federation or admin endpoints

## Out of scope

- Compromise of a node by an administrator with legitimate access to the data store (see README, Security model)
- Issues in downstream platforms (e.g. Ágora) unless they stem from a protocol-level flaw in this repository

## Auditing before you federate

Peers should review `CONTRIBUTING.md` and inspect `message.rs` plus the git tag they deploy. The SA version can be declared in the node's DID document for peer verification.
