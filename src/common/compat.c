/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "compat.h"

#include <string.h>

void *seer_memmem(const void *hay, size_t hay_len,
                  const void *needle, size_t needle_len)
{
    if (needle_len == 0)
        return (void *)hay;
    if (hay_len < needle_len)
        return NULL;

    const unsigned char *h = hay;
    const unsigned char *n = needle;
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        if (h[i] == n[0] && memcmp(h + i, n, needle_len) == 0)
            return (void *)(h + i);
    }
    return NULL;
}
