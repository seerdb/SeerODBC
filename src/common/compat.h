/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_COMPAT_H
#define SEER_COMPAT_H

/*
 * Portable replacements for libc functions that are GNU/BSD extensions and so
 * missing from some C runtimes (notably the Windows CRT under MinGW). Used
 * unconditionally on every platform - one code path, no per-caller #ifdef.
 */

#include <stddef.h>
#include <stdio.h>

/* Locate the first occurrence of the byte string needle[0..needle_len) within
 * hay[0..hay_len). Returns a pointer into hay, or NULL. Matches memmem(3):
 * a zero-length needle matches at the start of hay. */
void *seer_memmem(const void *hay, size_t hay_len,
                  const void *needle, size_t needle_len);

/* Duplicate at most n bytes of s (stopping early at a NUL), NUL-terminating the
 * result. Returns a malloc'd string the caller frees, or NULL on OOM. Matches
 * strndup(3). */
char *seer_strndup(const char *s, size_t n);

/* Case-insensitive strstr(3): the first occurrence of needle in hay ignoring
 * ASCII case, or NULL. An empty needle matches at hay. Returns a pointer into
 * hay (const cast away, as strstr does). */
char *seer_strcasestr(const char *hay, const char *needle);

/* Read one line (including any trailing newline) from stream into *lineptr,
 * growing the malloc'd buffer (*lineptr / *n) as needed - the caller frees it.
 * Returns the byte count, or -1 at EOF/error. Matches getline(3). */
ptrdiff_t seer_getline(char **lineptr, size_t *n, FILE *stream);

#endif /* SEER_COMPAT_H */
