<!--
SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors

SPDX-License-Identifier: Apache-2.0
-->

# SeerODBC

A clean-room **ODBC driver for Oracle Database**, written in C.

A *seer* is an oracle — hence the name. SeerODBC lets ODBC consumers (BI
tools, Microsoft-stack applications, anything that speaks ODBC) talk to an
Oracle database **without** the Oracle Instant Client, by speaking Oracle's
TNS/TTC wire protocol directly.

> **Status: working driver.** Connects, queries, and does DML in transactions
> against live Oracle through unixODBC. See
> [`docs/ODBC_CONFORMANCE.md`](docs/ODBC_CONFORMANCE.md) for the function set and
> [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design and progress log.

## What works

Validated live across five Oracle releases — **9i, 10g, 11g, 21c and 23ai**
(TTC field versions 2 through 24) — via `tests/odbc/run-matrix.sh`. The 10g–23ai
tier runs the full ODBC surface through unixODBC; 9i (the legacy fv2 / `TTI_ALL7`
dialect) is validated through the core API. 11g/21c/23ai are the public-CI tier;
9i and 10g stay local (their images aren't redistributable).

- **Connect & auth** — O5LOGON across the 10g (DES), 11g (AES-192/SHA-1) and
  12c (AES-256/PBKDF2) verifiers, 23ai fv24 fast-auth, and 9i O3LOGON (legacy
  DES); full Unicode (`*W`) entry points.
- **SQL** — queries, DML, transactions (commit/rollback/autocommit), the full
  scalar type set incl. NUMBER/DATE/TIMESTAMP/BINARY_FLOAT|DOUBLE/RAW, LOBs
  (CLOB/BLOB/BFILE) and LONG/LONG RAW, and the complete `SQL_C_*` conversion matrix
  incl. `SQL_C_WCHAR`.
- **PL/SQL** — anonymous blocks, stored procedures/functions via `{call}` /
  `{?=call}`, IN/OUT parameters, REF CURSOR result sets, and PL/SQL associative
  arrays (IN and OUT).
- **Binding & fetch** — `?` and named (`:name`) markers, array (bulk) binding
  with batch-error row status, data-at-execution (`SQLPutData`), block fetch,
  scrollable + updatable cursors (positioned UPDATE/DELETE, optional `FOR UPDATE`
  row locking), and large (multi-KB) LOB binds.
- **Catalog** — Tables, Columns, PrimaryKeys, ForeignKeys, Statistics,
  GetTypeInfo, Procedures, ProcedureColumns, SpecialColumns.
- **Advanced types** — SQL objects / ADTs (nested, collections-of-objects,
  objects-with-collection attributes), VARRAY / nested tables, REF, XMLType
  (fetch + bind, incl. LOB-backed), and 23ai JSON + VECTOR binds (every element
  type, incl. sparse f32/f64/i8 and binary).
- **Performance** — statement caching: a closed statement's parsed server cursor
  is kept open and re-executed without a re-parse when the same SQL is prepared
  again (transparent; the describe travels with the cursor).
- **Beyond ODBC** (via the core `seer_*` API) — Advanced Queuing (RAW / object /
  JSON payloads, array + multi-consumer), XA / two-phase commit, proxy
  authentication + DRCP, and TLS / TCPS transport.

## Goals

- Support the Oracle release range **9i through 23ai** (field versions 2–24),
  negotiating the wire form down to each server; **11g** remains the reference
  target.
- Implement the ODBC 3.x functions that cover real consumer usage, driven by
  the public **Microsoft ODBC Programmer's Reference**.
- Stay **clean-room**: no Oracle source, no decompiled binaries, no code
  copied from any other driver. Public references and our own packet
  captures only. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Architecture

Two layers, strictly separated (the protocol core does **not** know ODBC
exists):

```
  +-----------------------------+   src/odbc/   ODBC shim (the SQL* entry points)
  |  ODBC shim                  |
  +-----------------------------+
  |  TNS/TTC protocol core      |   src/tns/    speaks Oracle's wire protocol
  +-----------------------------+
```

The core is also exercised directly — without a Driver Manager — by the
`freeoracle` CLI (`tools/freeoracle/`), a `tsql`-style client for proving the
protocol against a real server.

## Building

Requirements: a C17 compiler, Meson + Ninja, OpenSSL >= 3.0, and (for the
driver shim) the ODBC headers from **unixODBC** or **iODBC**.

```sh
meson setup build
meson compile -C build
meson test -C build
```

Useful options: `-Dwith_tls=false`, `-Dbuild_tools=false`, `-Dbuild_tests=false`,
and `-Ddriver_libdir=<path>` to override where the driver shim installs (default
`<libdir>/odbc`, e.g. `/usr/lib64/odbc`).

If the ODBC headers (`sql.h`) are not installed, the build skips the driver
shim and still builds the protocol core and `freeoracle`.

### Linux

The primary target. Install the ODBC headers via `unixODBC-devel` (or `iODBC`)
and OpenSSL 3 via your distribution, then build as above.

### macOS

Builds on macOS (Apple Silicon and Intel) with Homebrew. OpenSSL 3 is keg-only
and the ODBC Driver Manager lives under the brew prefix, so point the toolchain
at both:

```sh
brew install meson ninja pkg-config openssl@3 unixodbc
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"
export CPPFLAGS="-I$(brew --prefix unixodbc)/include"
export LDFLAGS="-L$(brew --prefix unixodbc)/lib"
meson setup build
meson compile -C build
```

`iODBC` (`brew install libiodbc`) works too — the driver is Driver-Manager
neutral and links against neither. The shim builds as `libseerodbc.dylib`, with
symbol export handled by the linker's `-exported_symbols_list` (the macOS
equivalent of the Linux version script).

## License

[Apache-2.0](LICENSE), chosen over MIT/BSD for its explicit patent grant. The
repository is [REUSE 3.3](https://reuse.software) compliant — every file carries
SPDX copyright + license tags (trivial config under CC0-1.0).
