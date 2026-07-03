# Publishing `fstp-core` on crates.io

Do this after the GitHub repository is **public** and `cargo test --workspace` passes on `main`.

## Package checklist (v0.1.0)

- [ ] `crates/fstp-core/schema/gen-notification.proto` present (included in tarball)
- [ ] `authors` and `LICENSE` in `crates/fstp-core/Cargo.toml`
- [ ] `cargo publish -p fstp-core --dry-run` completes **verify** without errors
- [ ] Git tag `v0.1.0` matches `version` in `Cargo.toml`
- [ ] No uncommitted changes on the commit you publish from

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
