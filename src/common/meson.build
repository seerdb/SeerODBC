# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: Apache-2.0

common_sources = files(
  'charset.c',
  'log.c',
)

common_inc = include_directories('.')

libseercommon = static_library('seercommon',
  common_sources,
  include_directories : common_inc,
  dependencies : [iconv_dep],
)

common_dep = declare_dependency(
  link_with : libseercommon,
  include_directories : common_inc,
  dependencies : [iconv_dep],
)
