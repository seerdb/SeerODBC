<!--
SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors

SPDX-License-Identifier: Apache-2.0
-->

# ODBC conformance

The implemented ODBC **3.x** function set. The Driver Manager maps deprecated
2.x calls onto these, so they are not implemented separately (see the bottom).

Legend: [x] implemented & live-validated · [~] partial · [ ] not implemented

## Connection & environment

| Status | Function | Notes |
|--------|----------|-------|
| [x] | SQLAllocHandle / SQLFreeHandle | ENV / DBC / STMT |
| [x] | SQLSetEnvAttr / SQLGetEnvAttr | ODBC version |
| [x] | SQLConnect / SQLDriverConnect | DSN from odbc.ini; HOST/PORT/SERVICE keys, or `DBQ` as Oracle's ODBC driver takes it: Easy Connect `[//]host[:port]/service` (#362) or a TNS alias from tnsnames.ora ($TNS_ADMIN, $ORACLE_HOME/network/admin, /etc; #374) |
| [x] | SQLDisconnect | in manual-commit mode with a transaction open: 25000, the connection left up (every release; on 9i, whose replies don't say, from one query of `DBMS_TRANSACTION.LOCAL_TRANSACTION_ID`, #344) |
| [x] | SQLSetConnectAttr / SQLGetConnectAttr | autocommit (switching back ON commits the open transaction, #342); `SQL_ATTR_CONNECTION_DEAD` is true once the socket is gone, or once the server has ended the session over a live one (killed, instance down, lost contact, idle time; #340) |
| [x] | SQLGetInfo | server-specific answer table (identifier quote, schemas-not-catalogs, txn, scroll options, …) |
| [x] | SQLGetFunctions | incl. SQL_API_ODBC3_ALL_FUNCTIONS |
| [x] | SQLGetDiagRec / SQLGetDiagField | ORA-code → SQLSTATE mapping (a session the server ended: 08S01, and 08003 for ORA-01012); multi-record queue (array-DML row errors carry SQL_DIAG_ROW_NUMBER) |
| [x] | SQLEndTran | commit / rollback |

## Statements & results

| Status | Function | Notes |
|--------|----------|-------|
| [x] | SQLPrepare / SQLExecute / SQLExecDirect | `{call}` & inline ODBC escapes, `?`→`:n` |
| [x] | SQLBindParameter | IN / OUT / IN OUT, arrays (PARAMSET_SIZE) with batch-error row status, REF CURSOR |
| [x] | SQLParamData / SQLPutData | data-at-execution: stream a parameter (`SQL_DATA_AT_EXEC`) in chunks |
| [x] | SQLNumParams / SQLDescribeParam | NumParams parses `?` / `:name` (deduped) |
| [x] | SQLNumResultCols / SQLDescribeCol / SQLColAttribute | |
| [x] | SQLBindCol / SQLFetch / SQLGetData | block fetch (ROW_ARRAY_SIZE), SQLGetData fragmentation |
| [x] | SQLFetchScroll | static scrollable cursor (NEXT/PRIOR/FIRST/LAST/ABSOLUTE/RELATIVE) |
| [x] | SQLSetPos | POSITION / REFRESH / positioned UPDATE / DELETE |
| [x] | SQLSetCursorName / SQLGetCursorName | generated `SQL_CURn` names; `UPDATE` / `DELETE ... WHERE CURRENT OF name` rewritten to the named cursor's current ROWID (Oracle has `CURRENT OF` only in PL/SQL) |
| [x] | SQLRowCount / SQLCloseCursor / SQLFreeStmt | |
| [x] | SQLSetStmtAttr / SQLGetStmtAttr | paramset/row-array size, bind type, concurrency (SQL_CONCUR_LOCK → FOR UPDATE), status ptrs |

## Catalog (data-dictionary backed)

| Status | Function | Notes |
|--------|----------|-------|
| [x] | SQLTables / SQLColumns | |
| [x] | SQLPrimaryKeys / SQLForeignKeys | |
| [x] | SQLStatistics | ALL_INDEXES / ALL_IND_COLUMNS |
| [x] | SQLGetTypeInfo | type table, per release (TIMESTAMP from 9i, BINARY_FLOAT / DOUBLE from 10g); attributes as SQLColAttribute reports them |
| [x] | SQLProcedures / SQLProcedureColumns | ALL_OBJECTS / ALL_ARGUMENTS |
| [x] | SQLSpecialColumns | ROWID for SQL_BEST_ROWID |
| [x] | SQLTablePrivileges / SQLColumnPrivileges | ALL_TAB_PRIVS / ALL_COL_PRIVS: granted rights, not an owner's own |

## Unicode (`*W`)

Exporting `SQLConnectW` makes the DM treat the driver as Unicode and route wide
apps to the `*W` entry points; ANSI apps stay on the A functions. Implemented:
`SQLConnectW`, `SQLDriverConnectW`, `SQLPrepareW`, `SQLExecDirectW`,
`SQLGetDiagRecW`, `SQLGetInfoW`, `SQLDescribeColW`, `SQLColAttributeW`,
`SQLTablesW`, `SQLColumnsW`, `SQLGetTypeInfoW`. UTF-16 ↔ UTF-8 both directions;
the DM bridges any `*W` not listed here to the A function. `SQL_C_WCHAR` bind
and fetch are supported regardless.

## Implemented since the first cut

`SQLMoreResults` (implicit result sets, 12c and later, `SQL_BATCH_SUPPORT` saying
so per release, #312; and on every release a query run with a parameter array,
one result set per parameter set, `SQL_PARAM_ARRAY_SELECTS` = `SQL_PAS_BATCH`, #431),
`SQLCancel` (data-at-exec abort + in-band break), `SQLNativeSql`, `SQLBrowseConnect` (iterative connect), and the full
descriptor API (`SQLGetDescField` / `SQLGetDescRec` read path; `SQLSetDescField` /
`SQLSetDescRec` write path) on the implicit ARD/APD/IRD/IPD reachable via
`SQLGetStmtAttr`. Writing a descriptor field updates the same bind/parameter array
that execute and fetch consume, so it is equivalent to `SQLBindCol` (ARD) or the
value/type halves of `SQLBindParameter` (APD/IPD); the IRD is read-only (`HY016`).
`SQLCopyDesc` copies records (and, within one class, the header fields) between
any two of them, e.g. a SELECT's ARD and IRD to an INSERT's APD and IPD to copy
rows. Explicitly allocated descriptors (`SQLAllocHandle(SQL_HANDLE_DESC)`) are
application descriptors of the connection: set as a statement's ARD they are shared
in place (two statements can fetch into the same buffers), as its APD they supply
the values at execute; their records are their own, the header fields (array size,
bind type and offset) stay the statement's. Freed while in use, the statements go
back to their implicit descriptors.

## Scalar functions (`{fn ...}`)

The preprocessor translates the ODBC scalar functions (Appendix E) into Oracle
SQL, and `SQL_STRING_FUNCTIONS`, `SQL_NUMERIC_FUNCTIONS`,
`SQL_TIMEDATE_FUNCTIONS`, `SQL_SYSTEM_FUNCTIONS`, `SQL_CONVERT_FUNCTIONS`, the
`SQL_TIMEDATE_*_INTERVALS` and the `SQL_CONVERT_<type>` masks report what it
translates on the connected release (#301). The names Oracle shares (ABS, MOD,
ROUND, CONCAT, REPLACE, SOUNDEX, EXTRACT and so on) go through unchanged. The
others become Oracle forms, for example LOCATE → INSTR, LEFT → SUBSTR,
LOG → LN, `USER()` → USER, and CONVERT(v, SQL_INTEGER) → TRUNC(CAST(v AS NUMBER)).
How each family behaves:

- **Date and time:**
  - DAYOFWEEK counts from Sunday whatever NLS_TERRITORY says. WEEK starts weeks
    on Sunday, and week 1 holds January 1.
  - DAYNAME and MONTHNAME are in the session's language.
  - Oracle has no TIME type, so CURTIME and CURRENT_TIME return the current
    DATE with its time of day.
  - TIMESTAMPDIFF counts whole intervals from the first value to the second,
    rounded toward zero; it has no FRAC_SECOND.
  - From 9i, NOW, CURRENT_TIMESTAMP and TIMESTAMPADD keep TIMESTAMP's type and
    fraction (LOCALTIMESTAMP, INTERVAL arithmetic). 8i has neither, so it uses
    SYSDATE and day arithmetic, with no FRAC_SECOND. EXTRACT is Oracle's own on
    every release (#308).
- **CONVERT** goes between text, numbers, DATE and TIMESTAMP. Text in a date
  form is parsed by the session's NLS_DATE_FORMAT. SQL_DOUBLE / SQL_REAL become
  BINARY_DOUBLE / BINARY_FLOAT from 10g, and NUMBER before.
- **Not available:** DIFFERENCE and DATABASE are neither translated nor
  advertised: Oracle has no equivalent and no catalogs. `RAND()` becomes
  DBMS_RANDOM.VALUE, but SQL can't seed it, so RAND is not advertised either.
- **Parameter markers:** a translation keeps the arguments that hold markers in
  their order, and may repeat one (`{fn REPEAT(?, 2)}` is still one parameter).
  When it would swap two of them (`{fn LOCATE(?, ?)}`), the statement is refused
  with HYC00 rather than binding values to the wrong arguments.

## Datetime and interval literals

`SQL_DATETIME_LITERALS` reports the escapes the preprocessor translates on the
connected release (#305):

- **`{d '...'}` and `{ts '...'}`** become Oracle's DATE and TIMESTAMP literals.
- **`{t '...'}`** becomes a DATE whose time of day is the value. Oracle has no
  TIME type.
- **`{INTERVAL [+|-] '...' qualifier}`** becomes Oracle's INTERVAL literal,
  from 9i. Every ODBC qualifier is accepted, with leading and seconds
  precision (`DAY(3) TO SECOND(1)`, `SECOND(2,2)`). Oracle has no unary minus
  for an interval, so a sign outside the quotes moves inside them. A minus on
  a value that already has one cancels it.
- **8i** has no INTERVAL type, so there the escape stays as written and isn't
  advertised.

## Fetching into C types

Each SQL_C_* type ODBC defines either gets the value converted or gets an
error. Before #314, a type the converter had no case for got the value's text,
reported as success.

- **The 13 `SQL_C_INTERVAL_*` structs** are filled from an INTERVAL value
  (9i+), or from a plain count for a single-field type:
  - the leading field takes in the larger ones, so `SQL_C_INTERVAL_HOUR` of
    1 day 2 hours is 26;
  - trailing parts the type has no field for, and fraction digits past the
    default seconds precision of 6, are cut with 01S07;
  - a year-month value into a day-time type, or the reverse, is 07006;
  - a leading field past 32 bits is 22015.
  The leading precision in the ARD isn't enforced.
- **`SQL_C_GUID`** gets 07006, because Oracle has no GUID type.
- **Integer, bit and floating-point targets** follow Appendix D (#329):
  - a value past the C type's range is 22003, and the buffer is left alone;
  - a dropped fraction is 01S07 (3.7 into `SQL_C_SLONG` is 3);
  - text that isn't a number is 22018;
  - a bit is 0 or 1, so 5 is 22003 and 1.5 is 1 with 01S07;
  - a 23ai BOOLEAN reads as 1 or 0;
  - binary data into a numeric type is 07006.
  Before, the value was cast without a word: 70000 into a `SQLSMALLINT` was
  4464, `'abc'` was 0, and a BOOLEAN TRUE read as 0.
- **`SQL_C_NUMERIC`** keeps a value's natural scale, so 123.45 is mantissa
  12345 at scale 2 (#332).
  - A NUMBER past the 128-bit mantissa (40 digits) moves its trailing zeros
    into a negative scale and stays exact.
  - Fraction digits that still don't fit are dropped with 01S07.
  - Significant integer digits past 128 bits are 22003, and so is a scale
    outside -128..127.
  - Non-numeric text is 22018.
  Before, the mantissa wrapped silently and text parsed as 0.
- **Text that won't parse as the target** (a date, an interval) is 22018.
- **A number or a date in a character buffer** (#336):
  - a value too long for the buffer may lose only its fraction digits
    (01004);
  - if the part before the decimal point doesn't fit, it is 22003 rather than
    a shorter number or date: 12345 in 4 bytes, or a DATE in 11;
  - text and binary values still truncate with 01004;
  - a length probe (no buffer) is unaffected;
  - a number into a date or time struct is 07006.
- **Date and time structs** (#334):
  - a DATE whose time isn't midnight, read into `SQL_C_TYPE_DATE`, gives
    01S07, since Oracle DATEs are described as `SQL_TYPE_TIMESTAMP`;
  - a TIMESTAMP's nonzero fraction read into `SQL_C_TYPE_TIME` gives 01S07;
  - text must be a real date, time or timestamp, bare or as an ODBC escape.
    Months, days (leap years Julian before 1583) and times are checked, so
    `2026-13-45` is 22018;
  - a text fraction scales by its digits, so `.5` is 500000000 ns;
  - a bare time fills `SQL_C_TYPE_TIME` but not a date or timestamp.
- **TIMESTAMP WITH TIME ZONE** reads as the time it was stored (#359). It is
  described as `SQL_TYPE_TIMESTAMP`, since ODBC has no type with a zone.
  - With a numeric offset, a struct gets the value's own wall-clock time, so
    `10:00 +02:00` is 10:00. The text form ends in the offset:
    `2026-11-20 10:00:00 +02:00`. Before, both gave the UTC time, 08:00, and
    dropped the zone.
  - With a region (`Europe/Berlin`), converting needs daylight-saving rules
    the wire doesn't carry. The value stays UTC, and the text says so with
    `+00:00`.
  - The display size counts the 7 characters of the offset.
- **The session's time zone** is set at login, as OCI sets it (#358), from
  9i. It is `ORA_SDTZ` if set: an offset or a region verbatim, `OS_TZ` for
  the OS's offset, `DB_TZ` for the database's zone. Otherwise it is the OS's
  UTC offset at login. Before, every session took the server's default zone.
- **TIMESTAMP WITH LOCAL TIME ZONE** reads in the session's zone (#358). The
  server sends it in `DBTIMEZONE`, and the driver moves it, as OCI does.
  - The driver reads both zones with one query, the first time a session
    reads such a value. It reads them again after an `ALTER SESSION`, or a
    PL/SQL block naming `TIME_ZONE`.
  - Only numeric offsets convert. A region on either side needs
    daylight-saving rules the wire doesn't carry, so the value then stays in
    `DBTIMEZONE`, with a warning in the log.
  - Not converted: LTZ attributes inside an object, and a zone changed in a
    way the driver can't see (`DBMS_SESSION` called from a stored
    procedure).
- **In a bound rowset**, a column that fails makes its row `SQL_ROW_ERROR`.
  The other rows are delivered with `SQL_SUCCESS_WITH_INFO`. A rowset where
  every row failed returns `SQL_ERROR`.
- **Strides:** fixed-length C types, `SQL_C_NUMERIC` and the interval structs
  included, are laid out at their own size in column-wise arrays, whatever
  `BufferLength` says.
- **`SQLGetData(SQL_ARD_TYPE)`** takes the type the column is bound with.
- **`SQL_C_DEFAULT`** is the ODBC default C type of the SQL type (#316): the
  type a column is described as, or a parameter's `ParameterType`.
  - DATE and TIMESTAMP columns fill a timestamp struct.
  - RAW, LONG RAW and BLOB give their bytes.
  - BINARY_DOUBLE and BINARY_FLOAT give a double and a float.
  - NUMBER and the character types give text.
  - A parameter's buffer is read the same way. Before, it was always taken as
    text: a struct or a number was refused, and on 8i RAW bytes were mangled.
- **A timestamp-struct parameter on 8i** goes out as a DATE (#318), because
  8.1.7 has no TIMESTAMP. The date and the time to the second arrive, and
  the fraction is dropped, as 9i and later drop it storing a TIMESTAMP into a
  DATE.

INTERVAL columns are still described as `SQL_VARCHAR`, so `SQL_C_DEFAULT` for
them is text.

## Parameter C types

Every C type ODBC defines is sent as its value (#322). Before, a C type the
bind had no case for had its buffer sent as text, reported as success.

- **The unsigned integers** go out as NUMBER. A `SQL_C_UBIGINT` past
  `INT64_MAX` is sent as its exact decimal.
- **`SQL_C_NUMERIC`** is an exact NUMBER, built from the struct's sign, scale
  and 128-bit mantissa. It doesn't depend on `NLS_NUMERIC_CHARACTERS`. A
  value outside NUMBER's range is 22003.
- **`SQL_C_GUID`** is sent as `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` text.
- **Character data for a numeric parameter** (`SQL_C_CHAR` / `SQL_C_WCHAR` with a
  numeric `ParameterType`) is an ODBC numeric literal, `.` the decimal point,
  bound as an exact NUMBER whatever the session's `NLS_NUMERIC_CHARACTERS`
  (#354). Text that is no such literal goes as text, for the server to convert
  or refuse; past NUMBER's range is 22003.
- **National parameters** (`SQL_WVARCHAR` / `SQL_WCHAR` / `SQL_WLONGVARCHAR`) go in the
  national charset when the database charset is not Unicode (9i's
  WE8ISO8859P1), so an NVARCHAR2 keeps what that charset lacks (#367). On a
  Unicode database they stay database-charset text, which loses nothing and
  keeps VARCHAR2 indexes usable.
- **Character data for a datetime parameter** is an ODBC date, time or
  timestamp literal (bare or `{d|t|ts '...'}`), bound as the native value, not
  text the server would read by `NLS_DATE_FORMAT` (#356): a TIMESTAMP with its
  fraction (a DATE on 8i), a DATE, or a TIME as a DATE on 1970-01-01. Text
  that is no such literal goes as text.
- **`SQL_C_BIT`** is a boolean only for a `SQL_BIT` parameter: a BOOLEAN on
  23ai and later, a NUMBER before. For any other `ParameterType` it is the
  number 0 or 1, which a character column stores as "0" or "1" on every
  release (#327). Before, 23ai stored `TRUE` and a CHAR(1) refused it.
- **All 13 interval C types** (9i+) become INTERVAL YEAR TO MONTH or DAY TO
  SECOND:
  - only the fields the type names are read;
  - a leading field past its usual range is carried, so `SQL_C_INTERVAL_HOUR`
    30 is 1 day 6 hours;
  - `fraction` is in microseconds (the default seconds precision 6), as fetch
    delivers it. Before, it was taken as nanoseconds, so 1.5 s went in as
    1.0005 s;
  - past a 9-digit leading field is 22015.
- **An unknown `ValueType`** is HY003 at `SQLBindParameter`. If a descriptor
  field sets one anyway, the execute fails with 07006.
- **Data-at-execution of a fixed-size C type** takes the type's size and
  ignores `StrLen_or_Ind`, as ODBC says (#323). A second `SQLPutData` piece
  is HY019. Before, the length was honoured and the bind read past the
  buffer.

## SQL-92 capabilities in SQLGetInfo

The SQL-92 description masks say which statement forms each release accepts
as written (#306). `check_sql92_info` runs one statement per bit on every tier
and requires the bit to be set exactly when its statement runs. Oracle's own
spellings of a form don't count. `DROP TABLE ... CASCADE CONSTRAINTS`,
`ALTER TABLE ... MODIFY` and an implicit ON DELETE NO ACTION set no bit,
because the SQL-92 text (`CASCADE`, `ALTER COLUMN ... SET DEFAULT`, `ON DELETE
NO ACTION`) is refused.

- **Schema names** qualify tables in DML and DDL, indexes, privileges and
  procedure calls (`SQL_SCHEMA_USAGE`). There are no catalogs.
- **DDL:**
  - CREATE TABLE takes constraints (named, deferrable), defaults and global
    temporary tables;
  - ALTER TABLE adds columns (`ADD x ...`, without COLUMN) and constraints,
    drops columns, and drops a constraint with CASCADE;
  - CREATE VIEW takes WITH CHECK OPTION, but not CASCADED or LOCAL;
  - CREATE SCHEMA AUTHORIZATION;
  - CREATE and DROP INDEX, with ASC and DESC keys.
- **Foreign keys** take ON DELETE CASCADE and SET NULL. There is no ON UPDATE.
- **Releases differ:**
  - 8i has no ANSI joins, no CURRENT_DATE or CURRENT_TIMESTAMP, no simple
    CASE, COALESCE or NULLIF, and no DEFAULT in VALUES or SET;
  - EXCEPT is accepted from 21c;
  - INTERSECT, OVERLAPS, TRIM, `TRANSLATE ... USING` and EXTRACT work
    everywhere.
- **`SQL_KEYWORDS`** lists Oracle's reserved words that aren't ODBC keywords.
  None of them can name a column on any release.
- **Limits:**
  - 1000 columns per table (ORA-01792 past it);
  - 32 columns per index (ORA-01793);
  - 4000-character literals (ORA-01704);
  - procedure and user names as long as other identifiers (30, or 128 from
    12.2).

  Others, such as the select list, the statement length and the number of
  tables, report 0 because no fixed limit was found.

## SeerODBC-specific identifiers

Server features with no standard ODBC surface are exposed through
driver-specific identifiers. An application defines the numbers itself (they
are not in any Driver Manager header):

| Identifier | Value | Used with | Meaning |
|---|---|---|---|
| `SQL_DESC_SEER_ANNOTATIONS` | 19111 | `SQLColAttribute` (string) | 23ai column annotations as `name=value` lines |
| `SQL_ATTR_SEER_DML_ROW_COUNTS` | 19112 | `SQLSetStmtAttr` (`SQLLEN *`) | per-row affected counts of an array DML (12c+) |
| `SQL_DIAG_SEER_ERROR_OFFSET` | 19113 | `SQLGetDiagField` (`SQLINTEGER`) | the parse offset the server reported with an error |
| `SQL_DESC_SEER_VECTOR_DIMENSIONS` | 19114 | `SQLColAttribute` (numeric) | a VECTOR column's declared dimensions (0 = flexible) |
| `SQL_DESC_SEER_VECTOR_FORMAT` | 19115 | `SQLColAttribute` (numeric) | its element format: 2 FLOAT32, 3 FLOAT64, 4 INT8, 5 BINARY (0 = flexible) |

Diagnostics also follow the vendor's own clients: the native error of a failed
statement is its ORA number, and creating a PL/SQL object that compiled with
errors returns `SQL_SUCCESS_WITH_INFO` with SQLSTATE `01000`, native 24344.

## Not implemented (deliberate / future)

| Function | Why |
|----------|-----|
| SQLBulkOperations | Bookmark-based bulk ops; SeerODBC exposes no bookmarks. Reported unsupported by `SQLGetFunctions`; returns `HYC00`. `SQLSetPos` covers positioned UPDATE/DELETE. |

## Free from the Driver Manager (not implemented on purpose)

The DM maps ODBC 2.x calls onto our 3.x functions:
`SQLAllocEnv/Connect/Stmt → SQLAllocHandle`, `SQLError → SQLGetDiagRec`,
`SQLColAttributes → SQLColAttribute`, `SQLTransact → SQLEndTran`,
`SQLSetParam → SQLBindParameter`, `SQLExtendedFetch → SQLFetchScroll`, and the
`...Option` calls → the `...Attr` calls. The DM also owns Unicode A/W bridging
for any function where only one width is exported.

## Testing

- **Offline unit tests** (`tests/unit/`, no server): protocol codec (reader,
  writer, marshal), O5LOGON crypto vectors (10g/11g/12c), NUMBER/DATE/float
  codecs, the SQL preprocessor (`test_sqlprep`), and the SQL_C_* conversion
  matrix (`test_convert`). Run under ASan/UBSan via `meson test`.
- **Driver-level integration test** (`tests/odbc/test_integration.c`): drives
  the driver through the unixODBC Driver Manager against a live server (15
  checks across the surface, incl. data-at-execution). Self-gating - skipped
  (exit 77) unless
  `SEER_TEST_HOST/SERVICE/USER` are set, so offline `meson test` stays green.
  `SEER_TEST_RELEASE` names the server's release, which the skips key on:
  ```
  SEER_TEST_HOST=127.0.0.1 SEER_TEST_SERVICE=XE SEER_TEST_RELEASE=11 \
  SEER_TEST_USER=pyo SEER_TEST_PASS=pyo123 meson test -C build 'odbc integration'
  ```
  `tests/odbc/run-matrix.sh` runs it across every reachable server version and
  prints a support matrix — **all eight tiers, 8i to 26ai, pass** (8i in its own
  OALL8 dialect, 9i at fv2, 10g at fv4, 23ai natively at fv24). The script also
  runs the core-API suite (`tests/odbc/test_core.c`) on every tier.
  Both suites run one set of checks on every tier, 8i to 26ai, each skipped with
  its reason where the release lacks what it needs or SeerODBC doesn't reach it
  yet (`tests/odbc/gates.h`, keyed on the `SEER_TEST_RELEASE` the script passes
  per tier).
  Where the servers live is set by environment variables (`SEER_CONTAINER_HOST`
  for the container tiers, `SEER_9I_HOST` for the 9i VM, per-tier
  `SEER_<TIER>_{HOST,PORT,TARGET,USER,PASS}` overrides) or a gitignored
  `tests/odbc/matrix.env` (see `matrix.env.example`); `--only` / `--skip`
  select tiers, and an unreachable tier is reported and skipped. The run exits
  non-zero if any tier has a failing check.
- **Live validation**: each feature is exercised against the full
  8i/9i/10g/11g/18c/21c/23ai/26ai matrix through unixODBC (isql + C clients) and
  the core API. See
  `docs/ARCHITECTURE.md` "Protocol progress" and `docs/ROADMAP.md` for the
  per-feature inventory.
