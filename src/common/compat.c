/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "compat.h"

#include <ctype.h>
#include <stdlib.h>
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

char *seer_strndup(const char *s, size_t n)
{
    size_t len = 0;
    while (len < n && s[len] != '\0')
        len++;
    char *p = malloc(len + 1);
    if (p == NULL)
        return NULL;
    memcpy(p, s, len);
    p[len] = '\0';
    return p;
}

char *seer_strcasestr(const char *hay, const char *needle)
{
    if (needle[0] == '\0')
        return (char *)hay;
    for (; *hay != '\0'; hay++) {
        const char *h = hay;
        const char *n = needle;
        while (*h != '\0' && *n != '\0' &&
               tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
            h++;
            n++;
        }
        if (*n == '\0')
            return (char *)hay;
    }
    return NULL;
}

ptrdiff_t seer_getline(char **lineptr, size_t *n, FILE *stream)
{
    if (lineptr == NULL || n == NULL || stream == NULL)
        return -1;

    if (*lineptr == NULL || *n == 0) {
        size_t cap = 128;
        char  *nb  = realloc(*lineptr, cap);
        if (nb == NULL)
            return -1;
        *lineptr = nb;
        *n       = cap;
    }

    size_t pos = 0;
    int    c;
    while ((c = fgetc(stream)) != EOF) {
        if (pos + 1 >= *n) {                 /* keep room for the NUL */
            if (*n > (size_t)-1 / 2)
                return -1;
            size_t newcap = *n * 2;
            char  *nb     = realloc(*lineptr, newcap);
            if (nb == NULL)
                return -1;
            *lineptr = nb;
            *n       = newcap;
        }
        (*lineptr)[pos++] = (char)c;
        if (c == '\n')
            break;
    }

    if (c == EOF && pos == 0)
        return -1;

    (*lineptr)[pos] = '\0';
    return (ptrdiff_t)pos;
}
