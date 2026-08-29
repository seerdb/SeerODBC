/* Known-answer test for Oracle Advanced Networking (ANO, ano.c), pinned to the
 * seerdb reference client's vectors: the round-1/round-2 containers, a real 26ai
 * server negotiation response (fixtures/ano_server_response.bin), the DH step
 * (deterministic private key 2**2000), and the AES-CBC + SHA-256 keystream MAC
 * wrap sequence. Every expected value is emitted by seerdb/common/ano*.py, so a
 * match proves this C port is byte-for-byte wire-compatible.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "ano.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Decode a hex string into `out` (must hold strlen(hex)/2 bytes); returns len. */
static size_t unhex(const char *hex, uint8_t *out)
{
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) {
            fprintf(stderr, "bad hex digit at offset %zu\n", 2 * i);
            assert(0 && "bad hex vector");
        }
        out[i] = (uint8_t)b;
    }
    return n;
}

/* Assert a (buf,len) equals the bytes of a hex string. */
static void eqx(const char *what, const uint8_t *got, size_t got_len, const char *hex)
{
    static uint8_t exp[8192];
    size_t n = unhex(hex, exp);
    if (got_len != n || memcmp(got, exp, n) != 0) {
        fprintf(stderr, "FAIL %s: got %zu bytes, want %zu\n", what, got_len, n);
        assert(0 && "vector mismatch");
    }
}

/* --- reference vectors (from seerdb/common/ano*.py) --- */

static const char *ROUND1 =
    "deadbeef00970b2002000004000004000300000000000400050b200200000800010000101c66ec28"
    "ea00120001deadbeef00030000000400040001000200030001000300000000000400050b200200000"
    "20003e0e100020006fcff0002000300000000000400050b200200000900010001080a06020f101100"
    "010002010003000200000000000400050b20020000060001000103040506";

static const char *ROUND2 =
    "deadbeef01190b200200000100000300010000000001000001e78ec74b8ce8692c4c767a3ff682721"
    "c77af8998f68fe1179602d0944600b3c608dca250e576398cabbc7222296640a652984dd05f3b8dc2"
    "0f140f3209f3235ca19cc519737bc10558ef609dd524639ad81a4ad89f2e72f5707e2269009c77638"
    "fb75f0c97e7202b4a2de5b2a95df737efba1b60104dc8fe97521be6d893dd871af37d008ee176bc2d"
    "6406bfd24f0b28c711b3c517d7f924b2949c5c5ca8b6ada7c21776f3bf35b47ee2cbc89cc507401a7"
    "cbe6e7ff0f77139c45416c832076332ec7e4a1b94b831425882213ebcf0779ba582d1f8a16eb982b0"
    "412979b313859331785e2d1480fcf6b71d591e4d0ddfc1a12650dc9d62e47798b36308ffb680";

static const char *CLIENT_PUB =
    "e78ec74b8ce8692c4c767a3ff682721c77af8998f68fe1179602d0944600b3c608dca250e576398ca"
    "bbc7222296640a652984dd05f3b8dc20f140f3209f3235ca19cc519737bc10558ef609dd524639ad8"
    "1a4ad89f2e72f5707e2269009c77638fb75f0c97e7202b4a2de5b2a95df737efba1b60104dc8fe975"
    "21be6d893dd871af37d008ee176bc2d6406bfd24f0b28c711b3c517d7f924b2949c5c5ca8b6ada7c2"
    "1776f3bf35b47ee2cbc89cc507401a7cbe6e7ff0f77139c45416c832076332ec7e4a1b94b83142588"
    "2213ebcf0779ba582d1f8a16eb982b0412979b313859331785e2d1480fcf6b71d591e4d0ddfc1a126"
    "50dc9d62e47798b36308ffb680";

static const char *SESSION_KEY =
    "9fdad18fb702b3e508da93a8d058b6653fa4d21ff4b2e77660b7fea57c2057c4cc630510d3f2f101e"
    "2acd32fcac522b8e9582d5cc772c0029f3c2aa3ef9536dd80c9deaaec66ecd2494d4cec835480306a"
    "121529e69a77124320c3ed103948bc79d58917e6a9d44dd4da2382aec878e8c85ff83c2b843b62cf5"
    "5848cf45e5150ab42b1f51f53c48bb6f4813316ae0daff6685b1ea2d7972037a00e9496d6bdf3e122"
    "9b35b5aabfed2c09f55207bc4c9965eff85642356758f8066c78f0c8c72f14c948c805ed31d10a738"
    "41b6c620c5f434de3be941bbc4917e585ef83cdabd8f27dafc7fa6fd95925a88e980cb6d847e6814c"
    "1befae8432c46af4cd439459e0";

/* The client-side wrap() of five payloads, in sequence (stateful MAC keystream). */
static const char *WRAP_PT[5] = {
    "73656c65637420312066726f6d206475616c",     /* "select 1 from dual" */
    "",                                          /* empty */
    "78787878787878787878787878787878",         /* 16 * 'x' */
    "79797979797979797979797979797979797979797979797979797979797979",  /* 31 * 'y' */
    "00010203",
};
static const char *WRAP_CT[5] = {
    "28ef4d9c64924a1903e228676a26bd4f249890360591c3637613f598906b8c8f6f811744db01edfd3f"
    "ae6a33ee30626808cd53817d468da6c39f0714fd8ede1d0f00",
    "4d4365ee2557f408a2fc29318400424adbace7e8216ed16d5cbeb135b9377a040100",
    "e82002dc44e6dfc52c0221a5b9d5d7774943d0571695083b3a697328c1dac57bac1a2b915b36a79f25"
    "b5922aa3e0a6a00100",
    "2e2ccbaec910b0f500907427f41621a44e7a653c32afb5a76d913d8bb3f8166ff0d1ee4b46c8f1973d"
    "b2a9789d8a1054960c842919af0432841508fcab51d31b0200",
    "44a4e6a21c3e439d655a22d55f248b44a6e26ff01abc07d0fd35fe94b8653d68525a10309677b85e86"
    "a0f9c6a7ed51920d00",
};

int main(void)
{
    static uint8_t buf[8192];

    /* 1. Round-1 request is deterministic and byte-identical to the reference. */
    {
        uint8_t *r1 = NULL;
        size_t   r1len = 0;
        assert(seer_ano_build_round1(&r1, &r1len) == SEER_OK);
        eqx("round1", r1, r1len, ROUND1);
        free(r1);
    }

    /* 2. Parse the real 26ai (AES256+SHA256, required) negotiation response. */
    static uint8_t fixture[4096];
    FILE *f = fopen(SEER_ANO_FIXTURE, "rb");
    assert(f != NULL && "cannot open ano_server_response.bin");
    size_t fixlen = fread(fixture, 1, sizeof fixture, f);
    fclose(f);

    SeerAnoResponse ar;
    assert(seer_ano_parse_response(fixture, fixlen, &ar) == SEER_OK);
    assert(ar.enc_id == 17);          /* AES256 */
    assert(ar.int_id == 5);           /* SHA256 */
    assert(ar.have_dh);
    assert(ar.prime_len == 256);      /* 2048-bit DH group */
    assert(ar.server_pub_len == 256);
    assert(ar.server_iv_len == 20 &&
           memcmp(ar.server_iv, "foo bar baz bat quux", 20) == 0);

    /* 3. DH with the deterministic private key 2**2000 (256-byte big-endian). */
    uint8_t priv[256] = { 0 };
    priv[5] = 0x01;                   /* 2**2000 has its only set bit here */
    uint8_t *cpub = NULL, *sk = NULL;
    size_t   cpub_len = 0, sk_len = 0;
    assert(seer_ano_dh_priv(&ar, priv, sizeof priv,
                            &cpub, &cpub_len, &sk, &sk_len) == SEER_OK);
    eqx("client_pub", cpub, cpub_len, CLIENT_PUB);
    eqx("session_key", sk, sk_len, SESSION_KEY);

    /* 4. Round-2 container carries exactly that public key. */
    {
        uint8_t *r2 = NULL;
        size_t   r2len = 0;
        assert(seer_ano_build_round2(cpub, cpub_len, &r2, &r2len) == SEER_OK);
        eqx("round2", r2, r2len, ROUND2);
        free(r2);
    }

    /* 5. The client channel's wrap() sequence matches the reference byte-for-byte
     *    (the MAC keystream is stateful, so the sequence is fixed). */
    SeerAno *client = NULL;
    assert(seer_ano_channel_new(ar.enc_id, ar.int_id, sk, sk_len,
                                ar.server_iv, ar.server_iv_len,
                                /*client_side=*/true, &client) == SEER_OK);
    for (int i = 0; i < 5; i++) {
        size_t ptlen = unhex(WRAP_PT[i], buf);
        uint8_t *ct = NULL;
        size_t   ctlen = 0;
        assert(seer_ano_wrap(client, buf, ptlen, &ct, &ctlen) == SEER_OK);
        char label[16];
        snprintf(label, sizeof label, "wrap%d", i);
        eqx(label, ct, ctlen, WRAP_CT[i]);
        free(ct);
    }
    seer_ano_free(client);

    /* 6. A client channel and a server channel decrypt each other's packets,
     *    both directions, in lock-step (the crux of interoperability). */
    SeerAno *c = NULL, *s = NULL;
    assert(seer_ano_channel_new(17, 5, sk, sk_len, ar.server_iv, ar.server_iv_len,
                                true, &c) == SEER_OK);
    assert(seer_ano_channel_new(17, 5, sk, sk_len, ar.server_iv, ar.server_iv_len,
                                false, &s) == SEER_OK);
    for (int i = 0; i < 4; i++) {
        const char *msg = "select 42 from dual";
        size_t mlen = strlen(msg);
        uint8_t *ct = NULL, *pt = NULL;
        size_t   ctlen = 0, ptlen = 0;
        /* client -> server */
        assert(seer_ano_wrap(c, (const uint8_t *)msg, mlen, &ct, &ctlen) == SEER_OK);
        assert(seer_ano_unwrap(s, ct, ctlen, &pt, &ptlen) == SEER_OK);
        assert(ptlen == mlen && memcmp(pt, msg, mlen) == 0);
        free(ct); free(pt);
        /* server -> client */
        assert(seer_ano_wrap(s, (const uint8_t *)msg, mlen, &ct, &ctlen) == SEER_OK);
        assert(seer_ano_unwrap(c, ct, ctlen, &pt, &ptlen) == SEER_OK);
        assert(ptlen == mlen && memcmp(pt, msg, mlen) == 0);
        free(ct); free(pt);
    }
    /* A tampered ciphertext must fail the integrity check. */
    {
        const char *msg = "tamper me";
        uint8_t *ct = NULL, *pt = NULL;
        size_t   ctlen = 0, ptlen = 0;
        assert(seer_ano_wrap(c, (const uint8_t *)msg, strlen(msg), &ct, &ctlen) == SEER_OK);
        ct[0] ^= 0x01;
        assert(seer_ano_unwrap(s, ct, ctlen, &pt, &ptlen) == SEER_EPROTO);
        free(ct); free(pt);
    }
    seer_ano_free(c);
    seer_ano_free(s);

    free(cpub);
    free(sk);
    seer_ano_response_free(&ar);

    (void)fixlen;
    printf("ano: all known-answer vectors match\n");
    return 0;
}
