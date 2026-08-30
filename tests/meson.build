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

# Request-boundary (session-state) piggyback known-answer test (§35).
test_reqbound = executable('test_reqbound',
  'unit/test_reqbound.c',
  dependencies : [seertns_dep],
)
test('request boundaries', test_reqbound)

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
