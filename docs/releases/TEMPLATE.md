One or two sentences: what this release is about, for someone deciding whether
to upgrade.

### New features

- **Headline phrase of the feature**: what it gives the user, the ODBC or core
  API surface it lives on, and any opt-in switch (#NNN).

### Fixes

- **Headline phrase of the fix**: the symptom a user would have seen, and on
  which servers (#NNN).

### Tooling

- Build, test and CI changes worth knowing about (skip dependabot / pure-CI
  noise).

### Validation status (honest)

- **Live, full matrix green:** the tiers `tests/odbc/run-matrix.sh` passed on,
  and against what (lab servers, a proxy, a capped field version).
- **GitHub CI (public tier):** the container images CI ran.
- **Not validated:** tiers or features proved only offline, or not at all.
- **Known flakes / limitations.**

### Installing

- **Linux, from source:** `meson setup build && meson compile -C build`, then
  register `build/src/odbc/libseerodbc.so` (see `packaging/odbcinst.ini.sample`).
- **Fedora:** `packaging/seerodbc.spec` builds from this tag's tarball.
- **macOS:** as Linux, with Homebrew's OpenSSL 3 and unixODBC.
