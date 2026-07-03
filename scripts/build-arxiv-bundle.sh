#!/usr/bin/env bash
# Pack LaTeX source + figure PDFs for arXiv upload.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCS="$ROOT/docs"
OUT="$DOCS/arxiv/submission"
ARCHIVE="$DOCS/arxiv/fstp-arxiv-source.tar.gz"

FIGURES=(
  fstp_hero.pdf
  fstp_state_machine.pdf
  fstp_dangling_pointer.pdf
  fstp_benchmark.pdf
)

rm -rf "$OUT"
mkdir -p "$OUT"

cp "$DOCS/FSTP-techPaper.tex" "$OUT/"

for fig in "${FIGURES[@]}"; do
  src="$DOCS/$fig"
  if [[ ! -f "$src" ]]; then
    echo "error: missing figure $src (run pdflatex in docs/ first)" >&2
    exit 1
  fi
  cp "$src" "$OUT/"
done

cat > "$OUT/00README.txt" <<'EOF'
FSTP technical paper — arXiv source bundle

Main TeX file: FSTP-techPaper.tex
Compiler: pdfLaTeX (recommended: run twice)

Figure files (same directory):
  fstp_hero.pdf
  fstp_state_machine.pdf
  fstp_dangling_pointer.pdf
  fstp_benchmark.pdf

Bibliography is embedded in the .tex file (thebibliography environment).
No .bib or .sty files beyond standard TeX Live packages are required.
EOF

mkdir -p "$DOCS/arxiv"
tar -czf "$ARCHIVE" -C "$OUT" .

echo "Created: $ARCHIVE"
echo "Contents:"
tar -tzf "$ARCHIVE"
