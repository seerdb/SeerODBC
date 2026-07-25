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

/* Locate the first occurrence of the byte string needle[0..needle_len) within
 * hay[0..hay_len). Returns a pointer into hay, or NULL. Matches memmem(3):
 * a zero-length needle matches at the start of hay. */
void *seer_memmem(const void *hay, size_t hay_len,
                  const void *needle, size_t needle_len);

#endif /* SEER_COMPAT_H */
