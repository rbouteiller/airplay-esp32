# Contributing

## Licensing of contributions

airplay-esp32 is GPL-3.0-or-later. Contributions are accepted on the same terms — inbound
equals outbound — so by opening a pull request you license your changes under
GPL-3.0-or-later and agree that they may be distributed with the Espressif binary
component exception in [LICENSE-EXCEPTION](LICENSE-EXCEPTION). You keep the copyright on
what you write.

Please sign off your commits with `git commit -s` to certify that you have the right to
submit them under [the Developer Certificate of Origin](https://developercertificate.org/),
and start new C and H files with the SPDX header used throughout the tree:

```c
// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later
```

Do not paste in code from projects whose license is incompatible with the GPL, and say
where the code came from when you bring in code that is compatible, so it can be recorded
in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Branches

**Open pull requests against `staging`, not `main`.**

`staging` is the integration branch. Every push to it replaces the rolling `beta`
pre-release, so merged work is immediately installable from the browser installer and can
be tried on hardware before it reaches anyone running a release. `main` carries stable
releases and moves only when a version is tagged.

## Formatting

This project uses `clang-format` 22.1.4 for C and header files. Use the pinned
development dependency so local formatting matches CI:

```sh
python3 -m pip install --user -r requirements-dev.txt
scripts/format.sh
```

To check formatting without changing files:

```sh
scripts/format.sh --check
```
