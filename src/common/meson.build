# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: Apache-2.0

common_sources = files(
  'charset.c',
  'compat.c',
  'log.c',
  'netcompat.c',
)

common_inc = include_directories('.')

# On Windows the sockets API lives in the ws2_32 import library (Winsock:
# WSAStartup, gethostname, recv/send, ...), not in the C runtime as on glibc. It
# propagates through common_dep to every consumer that touches the network.
common_platform_deps = [iconv_dep]
if host_machine.system() == 'windows'
  common_platform_deps += cc.find_library('ws2_32')
endif

libseercommon = static_library('seercommon',
  common_sources,
  include_directories : common_inc,
  dependencies : common_platform_deps,
)

common_dep = declare_dependency(
  link_with : libseercommon,
  include_directories : common_inc,
  dependencies : common_platform_deps,
)
