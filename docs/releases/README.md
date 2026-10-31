<!--
SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors

SPDX-License-Identifier: Apache-2.0
-->
# Release notes

One file per release, `x.y.z.md`, named exactly as the (unprefixed) tag. Each
is written in that release's PR (see `AGENTS.md`, "Cutting a release") and
becomes the body of its GitHub Release: `release.yml` publishes it with
`gh release create --notes-file`, above GitHub's auto-generated list of merged
PRs and the "Full Changelog" link. A tag with no notes file here fails the
release workflow.

Start a new one from [`TEMPLATE.md`](TEMPLATE.md). The files hold the release
body only: no title (the Release is titled "SeerODBC x.y.z") and no license
header (it would show in the published body); their licensing is declared in
`REUSE.toml`.
