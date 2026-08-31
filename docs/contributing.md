# Contributing

## Requirements

ESP-IDF **v5.5 or newer**, tested against v5.5.2. Clone with submodules:

```bash
git clone --recursive https://github.com/rbouteiller/airplay-esp32
```

## Formatting

C and header files are formatted with `clang-format` 22.1.4 in LLVM style: 2-space indent,
80-column limit. See `.clang-format`.

```bash
python3 -m pip install --user -r requirements-dev.txt
scripts/format.sh           # format everything
scripts/format.sh --check   # check without modifying
```

## Linting

`clang-tidy` runs with the bugprone, performance, portability and readability checks
configured in `.clang-tidy`. It needs `build/compile_commands.json`, so build once first.

```bash
scripts/lint.sh         # check
scripts/lint.sh --fix   # attempt auto-fixes
```

## Pre-commit hook

A hook auto-formats staged C and H files and runs clang-tidy. Enable it once per clone:

```bash
git config core.hooksPath .githooks
```

## CI

On every push and pull request to `main`:

| Job | What it does |
| --- | --- |
| `format-check` | `clang-format` dry run over all C/H files, excluding `components/u8g2` |
| `lint-check` | `clang-tidy` against the build output |
| `output-backends` | Builds the S/PDIF and USB output backends so every backend keeps linking |
| `build` | Builds the full target matrix |

Tagging `vMAJOR.MINOR.PATCH` triggers a release, which validates the tag against
`version.txt` and publishes merged firmware binaries.

## Testing

There is no unit test framework — this is embedded firmware and testing means flashing
real hardware. When submitting a change, say which board and build environment you tested
on.

## Editing these docs

The site is built with [Zensical](https://zensical.org/) from Markdown in `docs/`. Every
page has an edit link in its top-right corner that takes you straight to the GitHub
editor, so small corrections need no local setup at all.

To preview locally:

```bash
python3 -m pip install -r docs/requirements.txt
zensical serve
```

Then open <http://127.0.0.1:8000>.

Configuration lives in `mkdocs.yml`. Zensical reads that format natively — it is the
successor to Material for MkDocs by the same team, so the file is unchanged from a
Material setup and switching back is just a dependency change.

The build runs in **strict mode**, so a broken internal link fails CI rather than shipping
a dead link. Adding a page means adding it to the `nav` section of `mkdocs.yml`.

Docs and code live in the same repository on purpose: a pull request that changes a GPIO
default or a Kconfig option should update the corresponding page in the same diff.
