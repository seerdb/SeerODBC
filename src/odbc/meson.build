# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: Apache-2.0

# The ODBC shim. Compiled only when sql.h was found (see top-level meson.build).
#
# Remaining planned files from docs/ARCHITECTURE.md (convert.c, catalog.c,
# descriptor.c) get added as those functions are implemented.
odbc_sources = files(
  'handles.c',
  'connect.c',
  'attrs.c',
  'exec.c',
  'results.c',
  'catalog.c',
  'diag.c',
  'info.c',
  'unicode.c',
)

# Pure, connection-free logic (SQL preprocessing, the type-conversion matrix,
# and the odbc.ini reader), in a static library so the offline unit tests can
# link it directly. Folded into the shim below; these symbols stay internal (the
# version script exports only SQL*).
odbc_pure = static_library('seerodbcpure',
  files('sqlprep.c', 'convert.c', 'odbcini.c'),
  include_directories : include_directories('.'),
  dependencies : [common_dep],
)
odbc_pure_dep = declare_dependency(
  link_with : odbc_pure,
  include_directories : include_directories('.'),
  dependencies : [common_dep],
)

odbc_map = meson.current_source_dir() / 'seerodbc.map'   # GNU ld version script
odbc_exp = meson.current_source_dir() / 'seerodbc.exp'   # ld64 export list (macOS)

# No libodbcinst / libiodbcinst: odbcini.c reads odbc.ini itself, so the driver
# has no run-time dependency on either Driver Manager's instlib and loads
# identically under unixODBC and iODBC.

# Install directory for the driver shim. The shim is a dlopen()ed plugin, not a
# linkable library, so it belongs under <libdir>/odbc (the Fedora convention and
# the directory odbcinst-generate probes to turn a bare "Driver = libseerodbc.so"
# into an absolute path), never in the general loader search path. Overridable
# via -Ddriver_libdir= for non-Fedora layouts.
driver_libdir = get_option('driver_libdir')
if driver_libdir == ''
  driver_libdir = get_option('libdir') / 'odbc'
endif

# Export only the SQL* symbols. This keeps the protocol core and OpenSSL symbols
# out of the host process's dynamic symbol table - the same "don't pollute the
# host process" reasoning that ruled out GLib. The mechanism is linker-specific:
#
#   GNU ld (Linux, *BSD): a version script for the export set, plus -Bsymbolic so
#     a *W wrapper that calls an ANSI SQL* function reaches OUR definition, not
#     the Driver Manager's identically-named global (which would get our internal
#     handle and reject it).
#   ld64 (macOS): -exported_symbols_list for the export set; two-level namespace
#     (the default) already binds intra-library calls to our own definitions, so
#     no -Bsymbolic equivalent is needed. seerodbc.map's "SQL*" becomes "_SQL*".
if host_machine.system() == 'darwin'
  odbc_export_args    = ['-Wl,-exported_symbols_list,' + odbc_exp]
  odbc_export_depends = odbc_exp
else
  odbc_export_args    = ['-Wl,--version-script=' + odbc_map, '-Wl,-Bsymbolic']
  odbc_export_depends = odbc_map
endif

seerodbc_lib = shared_library('seerodbc',
  odbc_sources,
  include_directories : include_directories('.'),
  dependencies : [seertns_dep, common_dep, odbc_pure_dep],
  link_args : odbc_export_args,
  link_depends : odbc_export_depends,
  install : true,
  install_dir : driver_libdir,
)
