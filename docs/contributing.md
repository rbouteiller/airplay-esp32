# Contributing

## Requirements

ESP-IDF **v5.5.5 or newer**. Sendspin, which is built into almost every image by default,
needs the WebSocket post-handshake callback that landed in v5.5.5; on an older 5.5.x
release build with `CONFIG_SENDSPIN_ENABLE=n`. PlatformIO gets a matching toolchain from
the pioarduino platform pinned in `platformio.ini`, so no manual ESP-IDF install is needed
for that route. Clone with submodules:

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

## Branches

**Open pull requests against `staging`, not `main`.**

`staging` is the integration branch. Every push to it rebuilds the firmware matrix and
replaces the rolling `beta` pre-release, so anything merged there is immediately
installable from the [browser installer](getting-started/flashing.md#beta-builds) and can
be tried on real hardware before it reaches anyone running a release.

`main` carries stable releases. It is what the documentation site is published from and
what the release install buttons serve, and it moves only when `staging` has proved itself
and a version is tagged.

`version.txt` on `staging` must stay ahead of the latest release or the beta job fails, so
bump it as soon as a release goes out.

!!! warning "Rebase before merging"

    A pull request is checked against `staging` **as it was when the check ran**. If
    another PR merges in the meantime, a green tick can go red on merge — two branches
    that touch different files merge without conflict but can still break the build
    together, which is exactly how the SPIFFS partition overflowed once already.
    Enable *Require branches to be up to date before merging* on `staging`, or rebase
    and wait for a fresh run before merging anything non-trivial.

## CI

On every pull request to `main` or `staging`, and on every push to `main`:

| Job | What it does |
| --- | --- |
| `format-check` | `clang-format` dry run over all C/H files, excluding `components/u8g2` |
| `lint-check` | `clang-tidy` against the build output |
| `output-backends` | Builds the S/PDIF and USB output backends so every backend keeps linking |
| `build` | Builds the target matrix |

A pull request that touches only Markdown skips the firmware jobs, so a docs typo does not
cost an ESP-IDF toolchain build.

The target list lives in `.github/workflows/targets.json`. A pull request builds only the
entries flagged `"core": true` — enough to cover every chip and every board support
directory — while a push to `main` and a push to `staging` build all of them. The matrix
does not fail fast, and the beta job publishes whatever succeeded, so one board failing to
compile does not withhold every other board's build.

Adding a target means an entry in `targets.json` **and** a matching
`docs/firmware/<name>.json` manifest whose `parts[0].path` is
`airplay2-receiver-<name>.bin`. The docs workflow silently drops a manifest whose binary is
missing from the release, so a target added here shows up in the browser installer only
once a release actually carries it.

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
