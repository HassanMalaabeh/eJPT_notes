#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_ROOT="${1:-"$ROOT_DIR/build/pdf"}"

if ! command -v pandoc >/dev/null 2>&1; then
  echo "Error: pandoc is required to convert Markdown to PDF." >&2
  echo "Install pandoc from https://pandoc.org/installing.html and try again." >&2
  exit 1
fi

mkdir -p "$OUTPUT_ROOT"
OUTPUT_ROOT="$(cd "$OUTPUT_ROOT" && pwd)"

find "$ROOT_DIR" -type f -name '*.md' -not -path "$ROOT_DIR/.git/*" -print0 |
  while IFS= read -r -d '' file; do
    if [[ "$file" == "$OUTPUT_ROOT"* ]]; then
      continue
    fi

    relative_path="${file#"$ROOT_DIR/"}"
    output_file="$OUTPUT_ROOT/${relative_path%.md}.pdf"
    mkdir -p "$(dirname "$output_file")"
    echo "Converting $relative_path -> ${output_file#"$ROOT_DIR/"}"
    pandoc "$file" \
      --from markdown \
      --to pdf \
      --output "$output_file"
  done

echo "All Markdown files converted. PDFs are located in: $OUTPUT_ROOT"
