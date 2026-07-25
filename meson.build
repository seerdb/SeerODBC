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
else
  # MinGW defaults printf/snprintf to Microsoft's msvcrt, which lacks the C99 'z'
  # (size_t) and other length modifiers the core's format strings use. Select
  # MinGW's C99-conformant stdio instead - fixes %zu/%zd both at compile time
  # (-Wformat) and, more importantly, at run time. Must be defined before <stdio.h>.
  add_project_arguments('-D__USE_MINGW_ANSI_STDIO=1', language : 'c')
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
iconv_dep   = dependency('iconv')   # libc on glibc; libiconv/win-iconv elsewhere

# iconv()'s second argument is 'char **' on glibc and GNU libiconv but
# 'const char **' on win-iconv (the POSIX/SysV signature, used by e.g. Fedora's
# mingw stack). Detect which so charset.c can type its input pointer to match and
# compile cleanly under either - the autotools ICONV_CONST idiom.
iconv_const = ''
if not cc.compiles('''#include <iconv.h>
int main(void) {
  char *in = 0, *out = 0;
  size_t inleft = 0, outleft = 0;
  iconv((iconv_t)0, &in, &inleft, &out, &outleft);
  return 0;
}''', dependencies : iconv_dep, args : ['-Werror'],
      name : 'iconv takes a non-const (char **) input argument')
  iconv_const = 'const'
endif
add_project_arguments('-DSEER_ICONV_CONST=' + iconv_const, language : 'c')

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
sql_h = cc.has_header('sql.h')
# On Windows sql.h is MinGW's native ODBC header, but porting the shim to it is a
# later phase of the Windows port (the native headers need <windows.h> included
# first for HWND/DWORD/GUID, SQLWCHAR is UTF-16 not UTF-32, symbol export moves to
# a .def, and DSNs live in the registry). Until then Windows builds the protocol
# core + freeoracle only.
build_driver = sql_h and host_machine.system() != 'windows'
if build_driver
  subdir('src/odbc')
elif not sql_h
  warning('ODBC headers (sql.h) not found - skipping the driver shim. ' +
          'Install unixODBC-devel or iODBC to build it.')
else
  message('Windows: ODBC shim deferred to a later phase of the port - ' +
          'building the protocol core and freeoracle only.')
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
