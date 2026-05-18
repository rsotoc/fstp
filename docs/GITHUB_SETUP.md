# GitHub repository setup

Repository target: `**rsotoc/fstp**` (private first, public when the paper and crates.io release are ready).

## 1. Verify locally

```bash
cd /path/to/fstp
cargo test --workspace
cargo fmt --all -- --check
```

Ensure `target/` is **not** tracked (root `.gitignore` excludes it).

## 2. Initialize git (if not already)

```bash
cd /path/to/fstp
git init
git branch -M main
git add .
git status   # confirm: no .env, no target/, no certs/
git commit -m "Initial import: FSTP protocol, agent, and documentation"
```

## 3. Create private GitHub repository

Using [GitHub CLI](https://cli.github.com/):

```bash
gh auth login
gh repo create rsotoc/fstp --private --source=. --remote=origin --push
```

Or create an empty private repo in the GitHub UI, then:

```bash
git remote add origin git@github.com:rsotoc/fstp.git
git push -u origin main
```

## 4. Repository settings (recommended)

- **Settings → General**: description *"Federated Sovereign Transport Protocol — verifiable coordination without disclosure"*
- **Settings → Security**: enable **Private vulnerability reporting**
- **Settings → Actions**: allow workflows (CI runs `cargo test` on push/PR)
- **About**: link to `docs/FSTP-techPaper.tex` or a Release PDF when available

## 5. First tag (optional, for git dependencies)

```bash
git tag -a v0.1.0 -m "FSTP 0.1.0 — initial protocol release"
git push origin v0.1.0
```

## 6. Later: public release checklist

- Publish whitepaper PDF as a GitHub Release asset
- `cargo publish -p fstp-core` on crates.io
- Submit academic paper with DOI → update `CITATION.cff`

