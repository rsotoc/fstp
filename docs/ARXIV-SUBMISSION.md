# arXiv submission — FSTP technical paper

**Published:** [arXiv:2607.00213](https://arxiv.org/abs/2607.00213) · DOI [10.48550/arXiv.2607.00213](https://doi.org/10.48550/arXiv.2607.00213)

The identifier stays. This file now has two parts: the **replacement** to upload (September 2026), and the historical checklist of the original submission.

## Replacement — September 2026

This revision adds **bounded re-emission**: a conforming agent refuses to send a received artifact to a third node unless the artifact's usage scope, or a fresh governance grant, authorizes that recipient. The DOI and the arXiv identifier do not change.

### What to upload

| File | Where it is |
|------|-------------|
| Main PDF | `docs/FSTP-techPaper.pdf` (27 pages) |
| Source | `docs/arxiv/fstp-arxiv-source.tar.gz` |

Rebuild before a later upload: `cd docs && pdflatex FSTP-techPaper.tex` twice, then `../scripts/build-arxiv-bundle.sh`. Confirm the PDF has no red `[TODO]` (the `\todo` command in the preamble is unused). Four figures remain.

### How to replace on arXiv

1. Log in → your papers → [arXiv:2607.00213](https://arxiv.org/abs/2607.00213) → **Replace**.
2. Upload `FSTP-techPaper.pdf`, then `fstp-arxiv-source.tar.gz`.
3. Replace the abstract and the comments with the blocks below. Title, authors, `cs.CR`, and cross-list `cs.DC` stay.
4. Preview the compiled PDF (figures and author list), then submit the replacement.

### Abstract (plain text — no LaTeX)

```
This paper introduces the Federated Sovereign Transport Protocol (FSTP), a synchronization boundary and transport layer for federated networks in which nodes have heterogeneous privacy requirements. Existing federation protocols leave data confinement to operator policy: they define message formats and delivery semantics but impose no structural constraint on what a conforming server may emit. FSTP addresses this gap by making data confinement a property of the protocol itself.

The central mechanism is a synchronization agent whose output type set is formally closed. Raw internal data cannot appear in any federation message because the constraint is enforced by the Rust type system at compile time, not by a runtime check. A received artifact carries a usage scope: a conforming agent refuses to re-emit it toward a third node unless that scope, or a fresh governance grant, authorizes the recipient. A contextual identity model derives a separate, unlinkable identifier for each federation relationship, preventing cross-context correlation structurally. A Blocklace-based event substrate provides tamper-evident, partially ordered logging with synchronization cost proportional to the symmetric difference between node states, and supports data erasure without breaking the hash chain.

The result is proof without exposure: a federation participant can verify that a process occurred, that a credential is authentic, and that an outcome is uncorrupted without accessing the internal data that produced these artifacts. FSTP is developed as the inter-node transport layer of Velyzor, a governance platform for institutions with demanding confidentiality requirements. The specification and reference implementation are released as open-source infrastructure under Apache 2.0; source code and figures accompany this paper.
```

### Comments

```
27 pages, 4 figures. Replacement adding bounded re-emission. Reference implementation: https://github.com/rsotoc/fstp
```

---

## Original submission (July 2026) — kept for the record

Historical checklist and copy-paste metadata used for the initial submission.

## Before you submit

1. Rebuild PDF: `cd docs && pdflatex FSTP-techPaper.tex` (run twice if references shift).
2. Open `FSTP-techPaper.pdf` and verify: title page authors, four figures, tables, no `[TODO]`.
3. Build source bundle: `../scripts/build-arxiv-bundle.sh` → `docs/arxiv/fstp-arxiv-source.tar.gz`.
4. Confirm author names match your arXiv profile (legal names if they differ from the PDF).

---

## arXiv web form — paste-ready fields

### Title

```
Federated Sovereign Transport Protocol (FSTP): Verifiable Coordination Without Disclosure
```

### Authors (order matters)

| # | Name (as on PDF) | Affiliation | Email |
|---|------------------|-------------|-------|
| 1 | Ramón Soto C. | Department of Accounting, University of Sonora, Hermosillo, Sonora, Mexico | ramon.soto@unison.mx |
| 2 | Liz Soto | Department of Mathematics, University of Sonora, Hermosillo, Sonora, Mexico | *(add if you want it public on arXiv)* |

In the arXiv author form: add affiliations exactly as above; mark corresponding author if required.

### Primary category

```
cs.CR  — Cryptography and Security
```

### Cross-list (optional, recommended)

```
cs.DC  — Distributed, Parallel, and Cluster Computing
```

Alternative second cross-list: `cs.NI` (Networking and Internet Architecture).

### Abstract (plain text — no LaTeX)

Copy this block into the abstract field. **Do not** include the Keywords line here; arXiv has a separate keywords field or you can skip it.

```
This paper introduces the Federated Sovereign Transport Protocol (FSTP), a synchronization boundary and transport layer for federated networks in which nodes have heterogeneous privacy requirements. Existing federation protocols leave data confinement to operator policy: they define message formats and delivery semantics but impose no structural constraint on what a conforming server may emit. FSTP addresses this gap by making data confinement a property of the protocol itself.

The central mechanism is a synchronization agent whose output type set is formally closed. Raw internal data cannot appear in any federation message because the constraint is enforced by the Rust type system at compile time, not by a runtime check. A contextual identity model derives a separate, unlinkable identifier for each federation relationship, preventing cross-context correlation structurally. A Blocklace-based event substrate provides tamper-evident, partially ordered logging with synchronization cost proportional to the symmetric difference between node states, and supports data erasure without breaking the hash chain.

The result is proof without exposure: a federation participant can verify that a process occurred, that a credential is authentic, and that an outcome is uncorrupted without accessing the internal data that produced these artifacts. FSTP is developed as the inter-node transport layer of Velyzor, a governance platform for institutions with demanding confidentiality requirements. The specification and reference implementation are released as open-source infrastructure under Apache 2.0; source code and figures accompany this paper.
```

### Comments (optional field on submission)

```
26 pages, 4 figures, 3 tables. Reference implementation in Rust (fstp-core). Protocol specification and code to be linked from GitHub release v0.1.0 upon announcement.
```

Update the last sentence with the arXiv ID or GitHub URL after the repo is public.

### Keywords (if the form asks)

```
federated transport; data confinement; synchronization agent; contextual identity; verifiable credentials; Blocklace; privacy by design
```

### Journal reference

Leave **empty** (preprint).

### Report number

Leave **empty** unless Universidad de Sonora assigns one.

### ACM classes (if prompted)

- **Primary:** `Security and privacy` → `Systems security` or general `Security and privacy`
- **Secondary:** `Networks` → `Network protocols`; `Security and privacy` → `Privacy protections`

Exact ACM widget labels vary by arXiv UI version; `cs.CR` + `cs.DC` is sufficient.

---

## Files to upload

| File | Role |
|------|------|
| `FSTP-techPaper.pdf` | **Main PDF** (required) — from `docs/FSTP-techPaper.pdf` |
| `fstp-arxiv-source.tar.gz` | **Source** (strongly recommended) — from `scripts/build-arxiv-bundle.sh` |

### Source tarball contents

```
FSTP-techPaper.tex
fstp_hero.pdf
fstp_state_machine.pdf
fstp_dangling_pointer.pdf
fstp_benchmark.pdf
00README.txt
```

arXiv compiles with pdfLaTeX. Figures are PDF (not SVG). Bibliography is inline `\begin{thebibliography}` — no `.bib` file needed.

---

## Submission workflow (arxiv.org)

1. **Login** → Submit → Start new submission.
2. **Select archive:** Computer Science (cs).
3. **Categories:** Primary `cs.CR`; cross-list `cs.DC`.
4. **Upload files:** PDF first, then source `.tar.gz`.
5. **Metadata:** paste title, authors, abstract, comments from above.
6. **Review compiled PDF** on arXiv’s preview (check figures and author list).
7. **License:** default arXiv.org perpetual non-exclusive license (standard for preprints). Code remains Apache 2.0 separately.
8. **Submit** → note submission number; wait for moderation (typically 1–2 business days).

---

## Immediately after announcement

When arXiv assigns `arXiv:YYYY.NNNNN`:

1. Update `CITATION.cff`:

```yaml
preferred-citation:
  type: article
  title: "Federated Sovereign Transport Protocol (FSTP): Verifiable Coordination Without Disclosure"
  authors:
    - family-names: "Soto"
      given-names: "Ramón"
    - family-names: "Soto"
      given-names: "Liz"
  year: 2026
  doi: 10.48550/arXiv.YYYY.NNNNN
  url: "https://arxiv.org/abs/YYYY.NNNNN"
```

2. Add to `README.md`:

```markdown
[![arXiv](https://img.shields.io/badge/arXiv-YYYY.NNNNN-b31b1b.svg)](https://arxiv.org/abs/YYYY.NNNNN)
```

3. GitHub Release `v0.1.0`: attach `FSTP-techPaper.pdf` + link abs/arxiv.

4. Optional: add to paper Data availability paragraph:

```latex
Source and benchmarks: \url{https://arxiv.org/abs/YYYY.NNNNN} and \url{https://github.com/rsotoc/fstp/tree/v0.1.0}.
```

(Rebuild PDF only if you want the ID inside the paper; linking from README/Release is enough for v1.)

---

## Suggested citation (after announcement)

```bibtex
@article{soto2026fstp,
  title   = {Federated Sovereign Transport Protocol ({FSTP}): Verifiable Coordination Without Disclosure},
  author  = {Soto, Ram{\'o}n and Soto, Liz},
  year    = {2026},
  eprint  = {YYYY.NNNNN},
  archivePrefix = {arXiv},
  primaryClass  = {cs.CR}
}
```

Replace `YYYY.NNNNN` with the assigned ID.
