# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: Apache-2.0

# Unit tests for the protocol core. Driver-level tests (via isql / a C
# harness through the Driver Manager) and fuzz harnesses land under
# tests/odbc/ and tests/fuzz/ as those layers come online.

# Point LeakSanitizer at the OpenSSL-globals suppressions file for every test run
# (harmless in a non-sanitized build - LSAN_OPTIONS is ignored there). Default so
# a plain `meson test` picks it up, keeping local and CI results identical.
add_test_setup('seer',
  is_default : true,
  env : ['LSAN_OPTIONS=suppressions=' + (meson.current_source_dir() / 'lsan.supp')],
)

test_reader = executable('test_reader',
  'unit/test_reader.c',
  dependencies : [seertns_dep],
)
test('reader bounds-checking', test_reader)

test_writer = executable('test_writer',
  'unit/test_writer.c',
  dependencies : [seertns_dep],
)
test('writer round-trip', test_writer)

test_marshal = executable('test_marshal',
  'unit/test_marshal.c',
  dependencies : [seertns_dep],
)
test('marshal codec', test_marshal)

test_auth = executable('test_auth',
  'unit/test_auth.c',
  dependencies : [seertns_dep],
)
test('o5logon crypto', test_auth)

test_number = executable('test_number',
  'unit/test_number.c',
  dependencies : [seertns_dep],
)
test('number/date decode', test_number)

test_json = executable('test_json',
  'unit/test_json.c',
  dependencies : [seertns_dep],
)
test('json->oson encoder', test_json)

# ANO native-encryption known-answer test (round-1/2 codec, DH, AES-CBC + SHA-256
# MAC), pinned to the seerdb reference vectors + a captured 26ai server response.
test_ano = executable('test_ano',
  'unit/test_ano.c',
  c_args : ['-DSEER_ANO_FIXTURE="' + meson.current_source_dir() + '/fixtures/ano_server_response.bin"'],
  dependencies : [seertns_dep],
)
test('ano native encryption', test_ano)

# ANO data integrity across a break/reset: the MAC keystreams re-derive, pinned
# to a captured 26ai session (AES256 + SHA256, a SQL error with DISABLE_OOB).
test_ano_reset = executable('test_ano_reset',
  'unit/test_ano_reset.c',
  c_args : ['-DSEER_ANO_RESET_FIXTURE="' + meson.current_source_dir() + '/fixtures/ano_reset_session.txt"'],
  dependencies : [seertns_dep, openssl_dep],
)
test('ano break/reset re-derivation', test_ano_reset)

# Request-boundary (session-state) piggyback known-answer test (§35).
test_reqbound = executable('test_reqbound',
  'unit/test_reqbound.c',
  dependencies : [seertns_dep],
)
test('request boundaries', test_reqbound)

# Sessionless-transaction TXN_SWITCH framing known-answer test (§31).
test_sessionless = executable('test_sessionless',
  'unit/test_sessionless.c',
  dependencies : [seertns_dep],
)
test('sessionless transactions', test_sessionless)

# Execute-RPA skip regression: a captured 26ai/fv27 response whose RPA field byte
# 0x04 collided with the OER token and desynced the old skip_rpa heuristic.
test_rpa_skip = executable('test_rpa_skip',
  'unit/test_rpa_skip.c',
  dependencies : [seertns_dep],
)
test('rpa skip (fv27)', test_rpa_skip)

# 9i (fv2) DML status reply regression: live 9.2.0.4 captures whose RPA counter
# has a 0x04 length byte (== the OER token) once the instance ages past 2^24.
test_fv2_status = executable('test_fv2_status',
  'unit/test_fv2_status.c',
  dependencies : [seertns_dep],
)
test('fv2 dml status', test_fv2_status)

# Oracle 8i login: OSESSKEY / OAUTH at 8i's fixed little-endian widths, byte for
# byte against seerdb's encoders, and reading the pairs reply.
test_o8i_login = executable('test_o8i_login',
  'unit/test_o8i_login.c',
  dependencies : [seertns_dep],
)
test('8i login', test_o8i_login)

# Oracle 8i OALL8 query / fetch calls, byte for byte against seerdb's encoders.
test_o8i_stmt = executable('test_o8i_stmt',
  'unit/test_o8i_stmt.c',
  dependencies : [seertns_dep],
)
test('8i oall8', test_o8i_stmt)

# A LOBOPS reply's content, whole or cut short (a short chunk is an error, not
# a silently truncated LOB).
test_lob_content = executable('test_lob_content',
  'unit/test_lob_content.c',
  dependencies : [seertns_dep],
)
test('lob content', test_lob_content)

# The fetch-only OALL8 that drains a REF CURSOR / implicit result, against the
# frame a live 11g answered (seerdb #1462).
test_fetch_only = executable('test_fetch_only',
  'unit/test_fetch_only.c',
  dependencies : [seertns_dep],
)
test('fetch-only oall8', test_fetch_only)

# Accept-and-reject stubs for features not on the thin wire: sharding (§37) + CQN
# (§38). Pure offline: the reject paths take no network.
test_stubs = executable('test_stubs',
  'unit/test_stubs.c',
  dependencies : [seertns_dep],
)
test('sharding + cqn stubs', test_stubs)

# A write to a socket the peer has closed must fail, not raise SIGPIPE and kill
# the host application (MSG_NOSIGNAL / SO_NOSIGPIPE). POSIX-only: socketpair.
if host_machine.system() != 'windows'
  test_sigpipe = executable('test_sigpipe',
    'unit/test_sigpipe.c',
    dependencies : [common_dep],
  )
  test('no SIGPIPE on a closed peer', test_sigpipe)

  # A reply that ends in a packet of exactly the fragment size must not wait
  # out the socket timeout for a continuation that never comes (§1.3).
  test_fragment_wait = executable('test_fragment_wait',
    'unit/test_fragment_wait.c',
    dependencies : [seertns_dep],
  )
  test('exact-size final packet', test_fragment_wait, timeout : 60)
endif

# Live two-phase-commit (XA/TPC) test against the core API. Self-gating: exits 77
# (skip) unless SEER_TEST_HOST/SERVICE/USER are set, so it is a no-op offline.
test_tpc = executable('test_tpc',
  'odbc/tpc_test.c',
  dependencies : [seertns_dep],
)
test('two-phase commit (live)', test_tpc, is_parallel : false, timeout : 60)

# Live request-boundary test (§35, core API). Self-gating: exits 77 offline.
test_reqbound_live = executable('reqbound_test',
  'odbc/reqbound_test.c',
  dependencies : [seertns_dep],
)
test('request boundaries (live)', test_reqbound_live, is_parallel : false, timeout : 60)

# Live sessionless-transaction test (§31, core API). Self-gating: exits 77 offline.
test_sessionless_live = executable('sessionless_test',
  'odbc/sessionless_test.c',
  dependencies : [seertns_dep],
)
test('sessionless transactions (live)', test_sessionless_live, is_parallel : false, timeout : 60)

# Live request-pipelining test (§32, core API). Self-gating: exits 77 offline.
test_pipeline_live = executable('pipeline_test',
  'odbc/pipeline_test.c',
  dependencies : [seertns_dep],
)
test('request pipelining (live)', test_pipeline_live, is_parallel : false, timeout : 60)

# Live SQL OBJECT bind test (core API). Self-gating: exits 77 (skip) offline.
test_objbind = executable('test_objbind',
  'odbc/objbind_test.c',
  dependencies : [seertns_dep],
)
test('object bind (live)', test_objbind, is_parallel : false, timeout : 60)

# Live Advanced Queuing (AQ) enqueue test (core API). Self-gating: exits 77 offline.
test_aq = executable('test_aq',
  'odbc/aq_test.c',
  dependencies : [seertns_dep],
)
test('advanced queuing (live)', test_aq, is_parallel : false, timeout : 60)

# Oracle 9i (fv2) core-API integration test. LOCAL ONLY: 9i can't be
# containerized (old kernel/glibc), so it is validated by us against a local 9i
# VM via tests/odbc/run-matrix.sh - and deliberately NOT registered as a meson
# test() so `meson test` / GitHub CI never reference 9i.
test_9i = executable('test_9i',
  'odbc/test_9i.c',
  dependencies : [seertns_dep],
)

# Oracle 8i (8.1.7) core-API integration test: LOCAL ONLY, as test_9i (8i is a
# VM), run by tests/odbc/run-matrix.sh and not registered as a meson test().
test_8i = executable('test_8i',
  'odbc/test_8i.c',
  dependencies : [seertns_dep],
)

# ODBC-shim pure logic (only when the driver is built). These link the
# sqlprep + convert static library directly - no Driver Manager, no server.
if build_driver
  test_sqlprep = executable('test_sqlprep',
    'unit/test_sqlprep.c',
    dependencies : [odbc_pure_dep],
  )
  test('sql preprocessing', test_sqlprep)

  test_convert = executable('test_convert',
    'unit/test_convert.c',
    dependencies : [odbc_pure_dep],
  )
  test('type conversion', test_convert)

  # The reader itself is portable and builds on Windows; only this test's harness
  # (mkdtemp/setenv/POSIX temp paths) is not yet ported. File-based odbc.ini also
  # matters less on Windows, where DSNs live in the registry - both land with the
  # registry/DSN work in a later phase - so skip it there for now.
  if host_machine.system() != 'windows'
    test_odbcini = executable('test_odbcini',
      'unit/test_odbcini.c',
      dependencies : [odbc_pure_dep],
    )
    test('odbc.ini reader', test_odbcini)
  endif

  # Driver-level integration test: through the Driver Manager against a live
  # server. Self-gating - exits 77 (skip) unless SEER_TEST_HOST/SERVICE/USER are
  # set, so it is harmless in an offline `meson test`. The driver .so to load is
  # baked in (overridable via SEER_DRIVER); point at a server with, e.g.:
  #   SEER_TEST_HOST=127.0.0.1 SEER_TEST_SERVICE=XE \
  #   SEER_TEST_USER=pyo SEER_TEST_PASS=pyo123 meson test 'odbc integration'
  odbc_dm_dep = cc.find_library('odbc', required : false)
  if odbc_dm_dep.found()
    test_integration = executable('test_integration',
      'odbc/test_integration.c',
      dependencies : [odbc_dm_dep],
      c_args : ['-DSEER_DRIVER_PATH="' + seerodbc_lib.full_path() + '"'],
    )
    # `depends` (not link_with) so the .so is built first but loaded only by the
    # Driver Manager at run time - linking it in would clash with the DM's
    # identically-named SQL* symbols.
    test('odbc integration', test_integration,
         depends : seerodbc_lib, is_parallel : false, timeout : 120)
  endif
endif
