# eJPT Notes

This repository contains study notes for the eLearnSecurity Junior Penetration Tester (eJPT) certification exam. The notes are organised by assessment domain and delivered as Markdown files.

## Converting the notes to PDF

You can export every Markdown file in the repository to a PDF using [Pandoc](https://pandoc.org/). A helper script, [`convert_repo_to_pdf.sh`](./convert_repo_to_pdf.sh), automates the process.

### Prerequisites

- [Pandoc](https://pandoc.org/installing.html)
- A LaTeX engine supported by Pandoc (for example, TeX Live or MiKTeX)

### Usage

```bash
./convert_repo_to_pdf.sh [output_directory]
```

- `output_directory` is optional. By default, PDFs are written to `build/pdf/` inside the repository.
- The script keeps the same directory layout as the Markdown files so that the generated PDFs remain organised.

### Example

```bash
./convert_repo_to_pdf.sh
```

The command above renders all Markdown files and places the resulting PDFs under `build/pdf/`. You can then open the PDFs individually or bundle the `build/pdf/` directory into an archive for offline study.

If you prefer to create a single PDF that concatenates all notes, you can run Pandoc directly:

```bash
find . -name '*.md' -print0 \
  | sort -z \
  | xargs -0 pandoc -s -o eJPT_notes.pdf
```

The `sort -z` step ensures the files are processed in a stable order. Adjust the sort logic if you need a specific chapter sequence.

## License

This project retains the original licensing terms from the upstream repository. Consult the upstream project for further details.
