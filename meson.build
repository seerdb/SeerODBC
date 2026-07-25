# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: Apache-2.0

project('seerodbc', 'c',
  version : '0.0.0',
  license : 'Apache-2.0',
  meson_version : '>=0.60.0',
  default_options : [
    'c_std=c17',
    'warning_level=3',
    'default_library=shared',
    'b_ndebug=if-release',
  ],
)

cc = meson.get_compiler('c')

# _GNU_SOURCE unlocks the glibc extensions the core relies on (and is harmless on
# the BSD libc under macOS). It is meaningless on Windows/MinGW, whose headers key
# off different feature macros, so scope it to the POSIX platforms.
if host_machine.system() != 'windows'
  add_project_arguments('-D_GNU_SOURCE', language : 'c')
endif

# ld64 (macOS) warns "ignoring duplicate libraries: '-liconv'" once per target:
# meson propagates iconv's -liconv through common_dep to every consumer and does
# not dedupe the flag across the several dependency paths. The duplicate is
# harmless - the linker ignores the extra copy - so silence the specific noise
# where the flag is supported. (Not an issue on glibc, where iconv is in libc and
# dependency('iconv') contributes no -l.)
if host_machine.system() == 'darwin' and cc.has_link_argument('-Wl,-no_warn_duplicate_libraries')
  add_project_link_arguments('-Wl,-no_warn_duplicate_libraries', language : 'c')
endif

# --- Dependencies ---------------------------------------------------------
openssl_dep = dependency('openssl', version : '>=3.0',
                         required : get_option('with_tls'))
iconv_dep   = dependency('iconv')   # libc on glibc; libiconv elsewhere

# Public header dir for the protocol core API (include/seer/seertns.h).
core_inc = include_directories('include')

# --- Components ------------------------------------------------------------
# Order matters: common -> tns -> odbc, since each declares a dependency the
# next consumes (common_dep, seertns_dep).
subdir('src/common')
subdir('src/tns')

# The ODBC shim needs the Driver Manager headers (sql.h, from unixODBC or
# iODBC). Build it only when those headers are present, so the protocol core
# and freeoracle still configure on a machine without unixODBC-devel.
build_driver = cc.has_header('sql.h')
if build_driver
  subdir('src/odbc')
else
  warning('ODBC headers (sql.h) not found - skipping the driver shim. ' +
          'Install unixODBC-devel or iODBC to build it.')
endif

if get_option('build_tools')
  subdir('tools/freeoracle')
endif

if get_option('build_tests')
  subdir('tests')
endif

summary({
    'TLS / crypto (OpenSSL)' : openssl_dep.found(),
    'ODBC driver shim'       : build_driver,
    'freeoracle CLI'         : get_option('build_tools'),
    'tests'                  : get_option('build_tests'),
  }, section : 'SeerODBC')
