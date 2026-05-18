# Publishing `fstp-core` on crates.io

Do this after the GitHub repository exists and `cargo test --workspace` passes on `main`.

## Prerequisites

- [crates.io](https://crates.io/) account and API token: `cargo login`
- Git tag matching the version in `crates/fstp-core/Cargo.toml` (e.g. `v0.1.0`)
- `repository` URL in `Cargo.toml` points to `https://github.com/rsotoc/fstp`

## Dry run

```bash
cd crates/fstp-core
cargo publish --dry-run
```

## Publish

```bash
cargo publish -p fstp-core
```

The crate `readme` is `crates/fstp-core/README.md`. The workspace root `README.md` remains the project landing page on GitHub.

## Versioning

Follow semver. Tag each release:

```bash
git tag -a v0.1.1 -m "fstp-core 0.1.1"
git push origin v0.1.1
```

Update `CITATION.cff` `version` when cutting releases intended for citation.
