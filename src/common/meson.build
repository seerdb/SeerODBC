# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: Apache-2.0

common_sources = files(
  'charset.c',
  'log.c',
)

common_inc = include_directories('.')

# iconv_dep is attached to common_dep (below), not to the static library: an
# archive does not link, so it needs no -liconv (charset.c's <iconv.h> is a
# system header), and listing the dep in both places made meson emit -liconv
# twice per consumer - harmless on glibc (iconv is in libc, so the dep is empty)
# but a "duplicate libraries" warning from ld64 on macOS, where it is -liconv.
libseercommon = static_library('seercommon',
  common_sources,
  include_directories : common_inc,
)

common_dep = declare_dependency(
  link_with : libseercommon,
  include_directories : common_inc,
  dependencies : [iconv_dep],
)
