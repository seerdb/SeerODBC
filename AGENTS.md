<!--
SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors

SPDX-License-Identifier: Apache-2.0
-->

# Notes for coding agents

This file collects repeatable procedures for automated / AI agents working on
SeerODBC. For the project's clean-room posture and contribution rules, read
[`CONTRIBUTING.md`](CONTRIBUTING.md) first — those requirements always apply.

## Cutting a release

SeerODBC has no automated package publishing: a release **is** an annotated,
signed git tag on `master` plus the GitHub Release the maintainer draws from it.
The Fedora RPM spec pulls its source tarball straight from that tag's archive
URL. An agent's job is to *prepare* the release on a branch and open the PR —
never to merge or tag it. The steps:

1. **Branch off `master`**, named `release-x.y.z` (e.g. `release-0.2.0`).

2. **Bump the version in all three places — they must stay in sync:**
   - [`meson.build`](meson.build) → `project(... version : 'x.y.z' ...)`
   - [`include/seer/seertns.h`](include/seer/seertns.h) →
     `SEERTNS_VERSION_MAJOR` / `_MINOR` / `_PATCH`
   - [`packaging/seerodbc.spec`](packaging/seerodbc.spec) → `Version: x.y.z`

   The `SEERTNS_VERSION_*` macros are the public API's advertised version for
   consumers (the ODBC shim, freeoracle, any future binding). They are **not**
   packed onto the wire — the driver announces a bare `PROGRAM=seerodbc` /
   `AUTH_PROGRAM_NM` with no version — so a stale macro is a cosmetic bug, not a
   protocol one. Keep them in sync anyway; a consumer may read them.

3. **Write the release notes.** SeerODBC keeps its notes in the GitHub Release
   body (there is no in-tree `CHANGELOG` yet — adopt one here if the project
   grows to want it). Cover what changed since the last tag
   (`git log <last-tag>..master`, or the full history for the first release),
   skipping dependabot / pure-CI noise. Bold the headline phrase of each entry
   and cite the issue/PR as `(#NNN)`. State validation status **honestly**:
   which Oracle tiers (10g / 11g / 21c / 23ai) were exercised live, and call out
   anything proved only against a local bed, a proxy, or CI containers rather
   than a real server.

4. **Open a PR** against upstream `master` following the normal fork→upstream
   flow: push the branch to your fork (the `github` remote, `lemenkov/SeerODBC`)
   and open the PR against upstream (`seerdb/SeerODBC`). Title it
   `Release x.y.z`. In the body, summarise the shipped features and repeat the
   honest validation status from the notes.

5. **Stop there. Do NOT merge the PR, and do NOT create or push the tag.** The
   maintainer reviews, merges, runs a final live-matrix pass
   (`tests/odbc/run-matrix.sh`), and pushes the tag. Tagging is what creates the
   GitHub Release and the tarball the Fedora spec consumes — it is deliberately
   a human step.

### Tag naming

Tag the release **unprefixed** — `0.2.0`, not `v0.2.0`. The Fedora spec's
`Source:` URL is built from a bare `%{version}`
(`%{url}/archive/%{version}/%{name}-%{version}.tar.gz`), so a `v`-prefixed tag
would break the tarball fetch. Use an annotated, signed tag
(`git tag -s 0.2.0 -m 'Release 0.2.0'`).

### Versioning

Follow semantic versioning against the **public C core API**
([`include/seer/seertns.h`](include/seer/seertns.h)) and the ODBC shim's
observable behaviour — that is the stable surface consumers pin to. Additive,
backward-compatible features are a **minor** bump; bug fixes are a **patch**; a
breaking change to the core API or ODBC surface is a **major** bump. The TNS/TTC
wire internals, the negotiated protocol/field versions, and everything under
`src/tns` are implementation detail and are **not** covered by semver.

While the project is pre-1.0 (`0.y.z`) nothing is frozen: APIs may still move
between minor versions, and `0.1.0` is deliberately an experimental first
reference point rather than a stability promise.
