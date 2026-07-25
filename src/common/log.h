/* Minimal leveled logging to stderr.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_COMMON_LOG_H
#define SEER_COMMON_LOG_H

typedef enum {
    SEER_LOG_ERROR = 0,
    SEER_LOG_WARN,
    SEER_LOG_INFO,
    SEER_LOG_DEBUG,
} SeerLogLevel;

void seer_log_set_level(SeerLogLevel level);

/* On MinGW the bare "printf" format archetype means Microsoft's msvcrt printf,
 * which lacks the C99 'z'/'ll' length modifiers - so -Wformat rejects our %zu.
 * We build with __USE_MINGW_ANSI_STDIO (C99-conformant printf at run time), so
 * check formats against the matching "gnu_printf" archetype. Elsewhere the plain
 * "printf" archetype is correct. */
#if defined(__MINGW32__)
#  define SEER_PRINTF_ARCHETYPE gnu_printf
#else
#  define SEER_PRINTF_ARCHETYPE printf
#endif

void seer_log(SeerLogLevel level, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(SEER_PRINTF_ARCHETYPE, 2, 3)))
#endif
    ;

#endif /* SEER_COMMON_LOG_H */
