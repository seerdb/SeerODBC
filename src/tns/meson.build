# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: Apache-2.0

tns_sources = files(
  'ano.c',
  'auth.c',
  'json.c',
  'lob.c',
  'marshal.c',
  'oson.c',
  'packet.c',
  'pipeline.c',
  'reader.c',
  'session.c',
  'stmt.c',
  'transport.c',
  'ttc.c',
  'types.c',
  'writer.c',
)

tns_inc = include_directories('.')

threads_dep = dependency('threads')   # pthread_once for race-free lazy init

libseertns = static_library('seertns',
  tns_sources,
  include_directories : [tns_inc, core_inc],
  dependencies : [openssl_dep, common_dep, threads_dep],
)

# Public dependency: the include dir carries the public API (include/seer/),
# the internal tns_inc carries reader.h etc. for in-tree consumers (tests).
seertns_dep = declare_dependency(
  link_with : libseertns,
  include_directories : [tns_inc, core_inc],
  dependencies : [openssl_dep, common_dep, threads_dep],
)
