# FSTP documentation

This directory contains the technical whitepaper source, figures, and build notes for the Federated Sovereign Transport Protocol.

## Whitepaper

| File | Description |
|------|-------------|
| [`FSTP-techPaper.tex`](FSTP-techPaper.tex) | Full technical paper (LaTeX source) |

The paper defines the three protocol primitives (Synchronization Agent, contextual identity, Blocklace), formal properties, threat model, and evaluation. A PDF release may be attached to GitHub **Releases** when the academic submission is ready; until then, build locally or read the `.tex` source.

### Build PDF locally

```bash
cd docs
pdflatex FSTP-techPaper.tex
bibtex FSTP-techPaper   # if bibliography is enabled
pdflatex FSTP-techPaper.tex
pdflatex FSTP-techPaper.tex
```

Generated artifacts (`*.aux`, `*.log`, `*.pdf`, etc.) are listed in the root [`.gitignore`](../.gitignore). Do not commit local PDF builds unless you intentionally publish a release artifact.

## Figures

| Figure | File |
|--------|------|
| Architecture overview | [`fgdp_architecture.svg`](fgdp_architecture.svg) |
| SA state machine | [`fstp_state_machine.svg`](fstp_state_machine.svg) |
| Dangling pointer (erasure) | [`fstp_dangling_pointer.svg`](fstp_dangling_pointer.svg) |
| Benchmark summary | [`fstp_benchmark.svg`](fstp_benchmark.svg) |
| Hero / overview | [`fgdp_hero.svg`](fgdp_hero.svg) |

Some filenames retain the earlier **FGDP** prefix; they refer to the same protocol family now branded as **FSTP**.

## Citing this work

Use [`CITATION.cff`](../CITATION.cff) at the repository root for software citation metadata. Update author and DOI fields when the paper is published.

## Code ↔ whitepaper map

| Document | Description |
|----------|-------------|
| [`WHITEPAPER-CODE-MAP.md`](WHITEPAPER-CODE-MAP.md) | Every Rust source file mapped to paper sections (§2–§6) |
| [`IDENTIDAD-HU03.md`](IDENTIDAD-HU03.md) | HU-03 passport to Ágora Common — E2E flow and closure checklist |
| [`MTLS-PRODUCTION.md`](MTLS-PRODUCTION.md) | Production mTLS; retiring `FSTP_DEV_*` flags (`FSTP_PROFILE=production`) |
| [`PEER-BOOTSTRAP.md`](PEER-BOOTSTRAP.md) | `pod_directory` → `POST /fstp/admin/peers` (IP-03) |

Module-level `//!` comments in `crates/*` repeat the same section references for in-IDE navigation.

## Related integration docs

| Document | Location |
|----------|----------|
| Ágora ↔ SA contract v1 | [`docs/contracts/agora-pod-agent-v1.md`](../../docs/contracts/agora-pod-agent-v1.md) |
| Ticket index §3.1 | [`docs/tickets/INDICE-ESTADO-2026-05.md`](../../docs/tickets/INDICE-ESTADO-2026-05.md) |
