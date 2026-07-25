/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "charset.h"

#include <errno.h>
#include <iconv.h>
#include <stdint.h>
#include <stdlib.h>

int seer_iconv(const char *from, const char *to,
               const char *in, size_t in_len,
               char **out, size_t *out_len)
{
    if (out)     *out = NULL;
    if (out_len) *out_len = 0;
    if (out == NULL || out_len == NULL)
        return -1;

    iconv_t cd = iconv_open(to, from);
    if (cd == (iconv_t)-1)
        return -1;

    /* Reject inputs whose size computation (in_len*2 + 16, then +1 for the NUL)
     * would wrap size_t - a wrapped, undersized buffer would overflow in the
     * iconv loop below. This rejects only unrepresentable sizes, not any real
     * value (in_len is an in-memory string length). */
    if (in_len > (SIZE_MAX - 17) / 2) {
        iconv_close(cd);
        return -1;
    }
    size_t cap = in_len * 2 + 16;
    char  *buf = malloc(cap + 1);
    if (buf == NULL) {
        iconv_close(cd);
        return -1;
    }

    /* SEER_ICONV_CONST is 'const' where iconv() takes 'const char **' (win-iconv)
     * and empty where it takes 'char **' (glibc, GNU libiconv) - see meson.build. */
    SEER_ICONV_CONST char *inbuf = (SEER_ICONV_CONST char *)in;
    size_t inleft = in_len;
    char  *outbuf = buf;
    size_t outleft = cap;

    while (inleft > 0) {
        size_t r = iconv(cd, &inbuf, &inleft, &outbuf, &outleft);
        if (r != (size_t)-1)
            continue;
        if (errno == E2BIG) {
            size_t used   = (size_t)(outbuf - buf);
            if (cap > (SIZE_MAX - 1) / 2) {   /* cannot grow (cap*2 + 1) without overflow */
                free(buf);
                iconv_close(cd);
                return -1;
            }
            size_t newcap = cap * 2;
            char  *nb     = realloc(buf, newcap + 1);
            if (nb == NULL) {
                free(buf);
                iconv_close(cd);
                return -1;
            }
            buf    = nb;
            outbuf = buf + used;
            outleft = newcap - used;
            cap    = newcap;
            continue;
        }
        /* EILSEQ / EINVAL: malformed input. Give up cleanly. */
        free(buf);
        iconv_close(cd);
        return -1;
    }

    iconv_close(cd);
    size_t used = (size_t)(outbuf - buf);
    buf[used] = '\0';
    *out     = buf;
    *out_len = used;
    return 0;
}
