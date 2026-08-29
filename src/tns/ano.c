/* Oracle Advanced Networking (ANO) — native encryption + data integrity.
 *
 * See ano.h and PROTOCOL.md §33. This is a faithful C port of seerdb's
 * common/ano.py (the negotiation codec + DH), common/ano_cipher.py (AES-CBC
 * with Oracle padding), common/ano_mac.py (the AES-keystream SHA-2 MAC) and
 * common/ano_session.py (the channel bridge). Every constant and layout is a
 * protocol fact the Oracle server enforces on the wire.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "ano.h"

#include "log.h"
#include "writer.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------- wire constants */

#define ANO_MAGIC       0xDEADBEEFu
#define ANO_VERSION     0x0B200200u   /* the modern-thin-client version the server keys off */
#define ANO_HEADER_LEN  13            /* magic(4)|len(2)|version(4)|count(2)|err(1) */

/* Service types. */
#define SVC_AUTH        1
#define SVC_ENCRYPTION  2
#define SVC_INTEGRITY   3
#define SVC_SUPERVISOR  4

/* Sub-packet type tags. */
#define SP_STRING   0
#define SP_BYTES    1
#define SP_UB1      2
#define SP_UB2      3
#define SP_UB4      4
#define SP_VERSION  5
#define SP_STATUS   6

/* Supervisor / auth service payload constants. */
static const uint8_t SUPERVISOR_CID[8] = { 0, 0, 16, 28, 102, 236, 40, 234 };
#define AUTH_MARKER       0xE0E1
#define AUTH_STATUS_NONE  0xFCFF

/* Offered algorithm id lists (null-prefixed), matching the reference client. */
static const uint8_t ENC_IDS[] = { 0, 1, 8, 10, 6, 2, 15, 16, 17 };
/*                                    RC4_40/56/128/256, DES56C, AES128/192/256 */
static const uint8_t INT_IDS[] = { 0, 1, 3, 4, 5, 6 };
/*                                    MD5, SHA1, SHA512, SHA256, SHA384 */

/* AES encryption ids -> key length. */
#define ENC_AES128 15
#define ENC_AES192 16
#define ENC_AES256 17
/* SHA-2 integrity ids. */
#define INT_SHA256 5
#define INT_SHA384 6
#define INT_SHA512 4

/* The constant server IV keys the MAC (never the cipher). */
#define AES_BLOCK 16

/* ------------------------------------------------------- subpacket builders */

/* A sub-packet: u16 payload-length | u16 type | payload. */
static void sp(SeerWriter *w, uint16_t type, const void *payload, size_t len)
{
    seer_writer_u16(w, (uint16_t)len);
    seer_writer_u16(w, type);
    seer_writer_bytes(w, payload, len);
}

static void sp_version(SeerWriter *w)
{
    uint8_t v[4] = { 0x0B, 0x20, 0x02, 0x00 };
    sp(w, SP_VERSION, v, sizeof v);
}

static void sp_u16(SeerWriter *w, uint16_t type, uint16_t v)
{
    uint8_t b[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    sp(w, type, b, sizeof b);
}

static void sp_ub1(SeerWriter *w, uint8_t v)
{
    sp(w, SP_UB1, &v, 1);
}

/* A UB2 array rides on the bytes tag: a magic|3|count prefix, then each u16. */
static void sp_ub2_array(SeerWriter *w, const uint16_t *vals, size_t n)
{
    SeerWriter p;
    if (!seer_writer_init(&p, 10 + 2 * n))
        return;
    seer_writer_u32(&p, ANO_MAGIC);
    seer_writer_u16(&p, 3);
    seer_writer_u32(&p, (uint32_t)n);
    for (size_t i = 0; i < n; i++)
        seer_writer_u16(&p, vals[i]);
    if (seer_writer_ok(&p))
        sp(w, SP_BYTES, p.buf, p.len);
    else
        w->error = true;
    seer_writer_free(&p);
}

/* A service: u16 type | u16 subpacket-count | u32 err=0 | subpackets. `body`
 * holds the already-built subpackets; `count` is how many. */
static void service(SeerWriter *w, uint16_t type, uint16_t count,
                    const uint8_t *body, size_t body_len)
{
    seer_writer_u16(w, type);
    seer_writer_u16(w, count);
    seer_writer_u32(w, 0);
    seer_writer_bytes(w, body, body_len);
}

/* Append service `type` whose body is the built sub-writer `s`, then free `s`.
 * A sub-writer allocation failure is propagated to `w` so the caller's single
 * seer_writer_ok(w) check at the end catches it (no truncated packet slips out). */
static void emit_service(SeerWriter *w, uint16_t type, uint16_t count, SeerWriter *s)
{
    if (seer_writer_ok(s))
        service(w, type, count, s->buf, s->len);
    else
        w->error = true;
    seer_writer_free(s);
}

/* --------------------------------------------------------- round-1 request */

SeerStatus seer_ano_build_round1(uint8_t **out, size_t *outlen)
{
    *out = NULL;
    *outlen = 0;

    SeerWriter w;
    if (!seer_writer_init(&w, 256))
        return SEER_ENOMEM;

    /* Container header; total length patched at the end (offset 4). */
    seer_writer_u32(&w, ANO_MAGIC);
    seer_writer_u16(&w, 0);              /* length placeholder                */
    seer_writer_u32(&w, ANO_VERSION);
    seer_writer_u16(&w, 4);              /* service count                     */
    seer_writer_u8(&w, 0);              /* err                                */

    /* Supervisor service (version, control-id, announced service list). */
    {
        SeerWriter s;
        if (!seer_writer_init(&s, 64)) { seer_writer_free(&w); return SEER_ENOMEM; }
        sp_version(&s);
        sp(&s, SP_BYTES, SUPERVISOR_CID, sizeof SUPERVISOR_CID);
        const uint16_t list[4] = { SVC_SUPERVISOR, SVC_AUTH, SVC_ENCRYPTION, SVC_INTEGRITY };
        sp_ub2_array(&s, list, 4);
        emit_service(&w, SVC_SUPERVISOR, 3, &s);
    }
    /* Auth service (version, marker, no-method status). */
    {
        SeerWriter s;
        if (!seer_writer_init(&s, 32)) { seer_writer_free(&w); return SEER_ENOMEM; }
        sp_version(&s);
        sp_u16(&s, SP_UB2, AUTH_MARKER);
        sp_u16(&s, SP_STATUS, AUTH_STATUS_NONE);
        emit_service(&w, SVC_AUTH, 3, &s);
    }
    /* Encryption service (version, offered ids, driver flag). */
    {
        SeerWriter s;
        if (!seer_writer_init(&s, 32)) { seer_writer_free(&w); return SEER_ENOMEM; }
        sp_version(&s);
        sp(&s, SP_BYTES, ENC_IDS, sizeof ENC_IDS);
        sp_ub1(&s, 1);
        emit_service(&w, SVC_ENCRYPTION, 3, &s);
    }
    /* Data-integrity service (version, offered ids). */
    {
        SeerWriter s;
        if (!seer_writer_init(&s, 32)) { seer_writer_free(&w); return SEER_ENOMEM; }
        sp_version(&s);
        sp(&s, SP_BYTES, INT_IDS, sizeof INT_IDS);
        emit_service(&w, SVC_INTEGRITY, 2, &s);
    }

    if (!seer_writer_ok(&w)) { seer_writer_free(&w); return SEER_ENOMEM; }
    seer_writer_patch_u16(&w, 4, (uint16_t)w.len);
    if (!seer_writer_ok(&w)) { seer_writer_free(&w); return SEER_ENOMEM; }

    *out = w.buf;
    *outlen = w.len;
    return SEER_OK;   /* ownership of w.buf transferred to caller */
}

/* --------------------------------------------------------- response parse */

/* Read a big-endian u16 at p (bounded by end); returns false past the end. */
static bool be16(const uint8_t *p, const uint8_t *end, uint16_t *v)
{
    if (p + 2 > end)
        return false;
    *v = (uint16_t)((p[0] << 8) | p[1]);
    return true;
}

SeerStatus seer_ano_parse_response(const uint8_t *body, size_t len,
                                   SeerAnoResponse *out)
{
    memset(out, 0, sizeof *out);

    /* Seek to the DEADBEEF magic (the container may sit behind a prefix). */
    const uint8_t magic[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    const uint8_t *start = NULL;
    if (len >= 4) {
        for (size_t i = 0; i + 4 <= len; i++) {
            if (memcmp(body + i, magic, 4) == 0) { start = body + i; break; }
        }
    }
    if (start == NULL)
        return SEER_EPROTO;

    /* Own a private copy so the returned DH pointers outlive the caller's body. */
    size_t clen = len - (size_t)(start - body);
    uint8_t *copy = malloc(clen ? clen : 1);
    if (copy == NULL)
        return SEER_ENOMEM;
    memcpy(copy, start, clen);
    out->owned = copy;

    const uint8_t *p = copy;
    const uint8_t *end = copy + clen;
    if (p + ANO_HEADER_LEN > end) { seer_ano_response_free(out); return SEER_EPROTO; }
    uint16_t count = (uint16_t)((p[10] << 8) | p[11]);
    uint8_t err = p[12];
    if (err != 0) { seer_ano_response_free(out); return SEER_EPROTO; }
    p += ANO_HEADER_LEN;

    for (uint16_t si = 0; si < count; si++) {
        if (p + 8 > end) { seer_ano_response_free(out); return SEER_EPROTO; }
        uint16_t stype = (uint16_t)((p[0] << 8) | p[1]);
        uint16_t subcount = (uint16_t)((p[2] << 8) | p[3]);
        p += 8;   /* type(2) + subcount(2) + err(4) */

        /* Walk this service's sub-packets, capturing what we need. */
        for (uint16_t k = 0; k < subcount; k++) {
            uint16_t plen, ptype;
            if (!be16(p, end, &plen) || !be16(p + 2, end, &ptype)) {
                seer_ano_response_free(out); return SEER_EPROTO;
            }
            const uint8_t *payload = p + 4;
            if (payload + plen > end) { seer_ano_response_free(out); return SEER_EPROTO; }

            /* Selected algorithm id is the service's second sub-packet (a UB1). */
            if (k == 1 && plen >= 1) {
                if (stype == SVC_ENCRYPTION)
                    out->enc_id = payload[0];
                else if (stype == SVC_INTEGRITY)
                    out->int_id = payload[0];
            }
            /* DH exchange: the data-integrity service carries 8 sub-packets;
             * indices 4..7 are generator, prime, server-public, server-iv. */
            if (stype == SVC_INTEGRITY && subcount >= 8) {
                switch (k) {
                case 4: out->generator = payload;  out->generator_len = plen;  break;
                case 5: out->prime = payload;      out->prime_len = plen;      break;
                case 6: out->server_pub = payload; out->server_pub_len = plen; break;
                case 7: out->server_iv = payload;  out->server_iv_len = plen;  break;
                default: break;
                }
            }
            p = payload + plen;
        }
    }

    out->have_dh = out->prime && out->generator && out->server_pub && out->server_iv;
    return SEER_OK;
}

void seer_ano_response_free(SeerAnoResponse *r)
{
    if (r == NULL)
        return;
    free(r->owned);
    memset(r, 0, sizeof *r);
}

/* -------------------------------------------------------- Diffie-Hellman */

SeerStatus seer_ano_dh_priv(const SeerAnoResponse *r,
                            const uint8_t *priv, size_t priv_len,
                            uint8_t **client_pub, size_t *client_pub_len,
                            uint8_t **session_key, size_t *session_key_len)
{
    *client_pub = *session_key = NULL;
    if (!r->have_dh || r->prime_len == 0)
        return SEER_EPROTO;

    SeerStatus st = SEER_ENOMEM;
    size_t n = r->prime_len;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *g = BN_bin2bn(r->generator, (int)r->generator_len, NULL);
    BIGNUM *p = BN_bin2bn(r->prime, (int)r->prime_len, NULL);
    BIGNUM *spub = BN_bin2bn(r->server_pub, (int)r->server_pub_len, NULL);
    BIGNUM *pv = BN_bin2bn(priv, (int)priv_len, NULL);
    BIGNUM *pub = BN_new();
    BIGNUM *shared = BN_new();
    uint8_t *cpub = malloc(n);
    uint8_t *sk = malloc(n);
    if (!ctx || !g || !p || !spub || !pv || !pub || !shared || !cpub || !sk)
        goto done;

    if (!BN_mod_exp(pub, g, pv, p, ctx) || !BN_mod_exp(shared, spub, pv, p, ctx)) {
        st = SEER_EPROTO;
        goto done;
    }
    if (BN_bn2binpad(pub, cpub, (int)n) < 0 || BN_bn2binpad(shared, sk, (int)n) < 0) {
        st = SEER_EPROTO;
        goto done;
    }
    *client_pub = cpub;       *client_pub_len = n;
    *session_key = sk;        *session_key_len = n;
    cpub = sk = NULL;         /* ownership transferred */
    st = SEER_OK;

done:
    free(cpub);
    free(sk);
    BN_free(pub);
    BN_clear_free(shared);
    BN_clear_free(pv);
    BN_free(spub);
    BN_free(p);
    BN_free(g);
    BN_CTX_free(ctx);
    return st;
}

SeerStatus seer_ano_dh(const SeerAnoResponse *r,
                       uint8_t **client_pub, size_t *client_pub_len,
                       uint8_t **session_key, size_t *session_key_len)
{
    if (!r->have_dh || r->prime_len == 0)
        return SEER_EPROTO;
    uint8_t *priv = malloc(r->prime_len);
    if (priv == NULL)
        return SEER_ENOMEM;
    if (RAND_bytes(priv, (int)r->prime_len) != 1) {
        free(priv);
        return SEER_EPROTO;
    }
    SeerStatus st = seer_ano_dh_priv(r, priv, r->prime_len,
                                     client_pub, client_pub_len,
                                     session_key, session_key_len);
    OPENSSL_cleanse(priv, r->prime_len);
    free(priv);
    return st;
}

SeerStatus seer_ano_build_round2(const uint8_t *client_pub, size_t len,
                                 uint8_t **out, size_t *outlen)
{
    *out = NULL;
    *outlen = 0;

    SeerWriter w;
    if (!seer_writer_init(&w, len + 32))
        return SEER_ENOMEM;
    seer_writer_u32(&w, ANO_MAGIC);
    seer_writer_u16(&w, 0);            /* length placeholder */
    seer_writer_u32(&w, ANO_VERSION);
    seer_writer_u16(&w, 1);            /* one service */
    seer_writer_u8(&w, 0);

    SeerWriter s;
    if (!seer_writer_init(&s, len + 8)) { seer_writer_free(&w); return SEER_ENOMEM; }
    sp(&s, SP_BYTES, client_pub, len);
    emit_service(&w, SVC_INTEGRITY, 1, &s);

    if (!seer_writer_ok(&w)) { seer_writer_free(&w); return SEER_ENOMEM; }
    seer_writer_patch_u16(&w, 4, (uint16_t)w.len);
    if (!seer_writer_ok(&w)) { seer_writer_free(&w); return SEER_ENOMEM; }

    *out = w.buf;
    *outlen = w.len;
    return SEER_OK;
}

/* ---------------------------------------------------------------- channel */

struct SeerAno {
    size_t          keysize;       /* 16/24/32 */
    uint8_t         enc_key[32];
    bool            has_mac;
    const EVP_MD   *md;
    size_t          mac_size;      /* digest size (block-aligned: 32/48/64) */
    EVP_CIPHER_CTX *send_ks;       /* persistent MAC keystream (chained CBC) */
    EVP_CIPHER_CTX *recv_ks;
    uint8_t         send_buf[64];  /* evolving keystream block (mac_size) */
    uint8_t         recv_buf[64];
};

static const EVP_CIPHER *aes_cbc(size_t keysize)
{
    switch (keysize) {
    case 16: return EVP_aes_128_cbc();
    case 24: return EVP_aes_192_cbc();
    case 32: return EVP_aes_256_cbc();
    default: return NULL;
    }
}

/* One-shot AES-CBC over a whole number of blocks, zero-padding disabled. */
static bool aes_cbc_oneshot(const uint8_t *key, size_t keysize, const uint8_t *iv,
                            const uint8_t *in, size_t inlen, uint8_t *out, bool enc)
{
    const EVP_CIPHER *c = aes_cbc(keysize);
    if (c == NULL)
        return false;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return false;
    int outl = 0, finl = 0;
    bool ok = (enc ? EVP_EncryptInit_ex(ctx, c, NULL, key, iv)
                   : EVP_DecryptInit_ex(ctx, c, NULL, key, iv)) == 1;
    if (ok) ok = EVP_CIPHER_CTX_set_padding(ctx, 0) == 1;
    if (ok) ok = (enc ? EVP_EncryptUpdate(ctx, out, &outl, in, (int)inlen)
                      : EVP_DecryptUpdate(ctx, out, &outl, in, (int)inlen)) == 1;
    if (ok) ok = (enc ? EVP_EncryptFinal_ex(ctx, out + outl, &finl)
                      : EVP_DecryptFinal_ex(ctx, out + outl, &finl)) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* Build one persistent, chained CBC keystream cipher (never finalised). */
static EVP_CIPHER_CTX *keystream_ctx(const uint8_t *base_key, uint8_t tag,
                                     const uint8_t *base_iv)
{
    uint8_t key[16];
    memcpy(key, base_key, 16);
    key[5] = tag;   /* per-direction keystream tag: 90 send / 180 recv */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return NULL;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, base_iv) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

SeerStatus seer_ano_channel_new(uint8_t enc_id, uint8_t int_id,
                                const uint8_t *session_key, size_t sk_len,
                                const uint8_t *server_iv, size_t iv_len,
                                bool client_side, SeerAno **out)
{
    *out = NULL;
    size_t keysize;
    switch (enc_id) {
    case ENC_AES128: keysize = 16; break;
    case ENC_AES192: keysize = 24; break;
    case ENC_AES256: keysize = 32; break;
    default: return SEER_EPROTO;   /* only AES is implemented */
    }
    if (sk_len < keysize)
        return SEER_EPROTO;

    const EVP_MD *md = NULL;
    if (int_id != 0) {
        switch (int_id) {
        case INT_SHA256: md = EVP_sha256(); break;
        case INT_SHA384: md = EVP_sha384(); break;
        case INT_SHA512: md = EVP_sha512(); break;
        default: return SEER_EPROTO;   /* only SHA-2 is implemented */
        }
    }

    SeerAno *a = calloc(1, sizeof *a);
    if (a == NULL)
        return SEER_ENOMEM;
    a->keysize = keysize;
    memcpy(a->enc_key, session_key, keysize);   /* AES key = shared[:keysize] */

    if (md != NULL) {
        a->has_mac = true;
        a->md = md;
        a->mac_size = (size_t)EVP_MD_get_size(md);   /* 32/48/64 */

        /* Seed: aes_key = shared[:5] | 0xFF (zero-filled to 16); one AES-CBC
         * pass over 32 zero bytes with IV = server_iv[:16] seeds base key+IV.
         * sk_len >= keysize >= 16 already, so only the IV length needs a guard. */
        if (iv_len < AES_BLOCK) { free(a); return SEER_EPROTO; }
        uint8_t seed_key[16] = { 0 };
        memcpy(seed_key, session_key, 5);
        seed_key[5] = 0xFF;
        uint8_t zero32[32] = { 0 };
        uint8_t seed[32];
        if (!aes_cbc_oneshot(seed_key, 16, server_iv, zero32, 32, seed, true)) {
            free(a);
            return SEER_EPROTO;
        }
        const uint8_t *base_key = seed;
        const uint8_t *base_iv = seed + 16;

        /* Client side: send tag 90, recv tag 180 (swapped for a server). */
        uint8_t send_tag = client_side ? 90 : 180;
        uint8_t recv_tag = client_side ? 180 : 90;
        a->send_ks = keystream_ctx(base_key, send_tag, base_iv);
        a->recv_ks = keystream_ctx(base_key, recv_tag, base_iv);
        if (a->send_ks == NULL || a->recv_ks == NULL) {
            seer_ano_free(a);
            return SEER_ENOMEM;
        }
        /* send_buf / recv_buf start as mac_size zero bytes (calloc'd). */
    }

    *out = a;
    return SEER_OK;
}

void seer_ano_free(SeerAno *a)
{
    if (a == NULL)
        return;
    if (a->send_ks) EVP_CIPHER_CTX_free(a->send_ks);
    if (a->recv_ks) EVP_CIPHER_CTX_free(a->recv_ks);
    OPENSSL_cleanse(a->enc_key, sizeof a->enc_key);
    free(a);
}

size_t seer_ano_max_plain(uint16_t sdu)
{
    return (sdu > 64) ? (size_t)sdu - 64 : 1;
}

/* Advance a keystream one block (in-place) and return the block pointer. */
static bool keystream_advance(EVP_CIPHER_CTX *ctx, uint8_t *buf, size_t n)
{
    uint8_t tmp[64];
    int outl = 0;
    if (EVP_EncryptUpdate(ctx, tmp, &outl, buf, (int)n) != 1 || (size_t)outl != n)
        return false;
    memcpy(buf, tmp, n);
    return true;
}

/* Compute the packet MAC: advance the send keystream, then MD(payload||block). */
static bool mac_compute(SeerAno *a, const uint8_t *payload, size_t len, uint8_t *mac)
{
    if (!keystream_advance(a->send_ks, a->send_buf, a->mac_size))
        return false;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (c == NULL)
        return false;
    unsigned int mlen = 0;
    bool ok = EVP_DigestInit_ex(c, a->md, NULL) == 1 &&
              EVP_DigestUpdate(c, payload, len) == 1 &&
              EVP_DigestUpdate(c, a->send_buf, a->mac_size) == 1 &&
              EVP_DigestFinal_ex(c, mac, &mlen) == 1;
    EVP_MD_CTX_free(c);
    return ok && mlen == a->mac_size;
}

/* Verify a received MAC: advance the recv keystream, then compare. */
static bool mac_verify(SeerAno *a, const uint8_t *payload, size_t len,
                       const uint8_t *received)
{
    if (!keystream_advance(a->recv_ks, a->recv_buf, a->mac_size))
        return false;
    uint8_t expected[64];
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (c == NULL)
        return false;
    unsigned int mlen = 0;
    bool ok = EVP_DigestInit_ex(c, a->md, NULL) == 1 &&
              EVP_DigestUpdate(c, payload, len) == 1 &&
              EVP_DigestUpdate(c, a->recv_buf, a->mac_size) == 1 &&
              EVP_DigestFinal_ex(c, expected, &mlen) == 1;
    EVP_MD_CTX_free(c);
    if (!ok || mlen != a->mac_size)
        return false;
    return CRYPTO_memcmp(expected, received, a->mac_size) == 0;
}

SeerStatus seer_ano_wrap(SeerAno *a, const uint8_t *pt, size_t len,
                         uint8_t **out, size_t *outlen)
{
    *out = NULL;
    *outlen = 0;

    /* plaintext ‖ MAC(plaintext) */
    size_t body = len + (a->has_mac ? a->mac_size : 0);
    size_t pad = (AES_BLOCK - body % AES_BLOCK) % AES_BLOCK;
    size_t ctlen = body + pad;

    uint8_t *buf = calloc(ctlen ? ctlen : AES_BLOCK, 1);
    uint8_t *cipher = malloc(ctlen ? ctlen : AES_BLOCK);
    if (buf == NULL || cipher == NULL) { free(buf); free(cipher); return SEER_ENOMEM; }

    if (len)
        memcpy(buf, pt, len);
    if (a->has_mac) {
        if (!mac_compute(a, pt, len, buf + len)) {
            free(buf); free(cipher);
            return SEER_EPROTO;
        }
    }
    /* zero padding is already in place (calloc); marker carries the count. */
    if (ctlen && !aes_cbc_oneshot(a->enc_key, a->keysize, (const uint8_t[16]){ 0 },
                                  buf, ctlen, cipher, true)) {
        free(buf); free(cipher);
        return SEER_EPROTO;
    }

    /* out = ciphertext ‖ (pad+1) ‖ 0x00 (key-fold flag, always 0). */
    uint8_t *w = malloc(ctlen + 2);
    if (w == NULL) { free(buf); free(cipher); return SEER_ENOMEM; }
    if (ctlen)
        memcpy(w, cipher, ctlen);
    w[ctlen] = (uint8_t)(pad + 1);
    w[ctlen + 1] = 0x00;

    free(buf);
    free(cipher);
    *out = w;
    *outlen = ctlen + 2;
    return SEER_OK;
}

SeerStatus seer_ano_unwrap(SeerAno *a, const uint8_t *ct, size_t len,
                           uint8_t **out, size_t *outlen)
{
    *out = NULL;
    *outlen = 0;

    /* Strip the trailing key-fold flag byte, then the padding marker. */
    if (len < 2)
        return SEER_EPROTO;
    size_t n = len - 1;              /* drop fold flag */
    uint8_t marker = ct[n - 1];      /* padding_count + 1 */
    size_t ctlen = n - 1;
    if (ctlen % AES_BLOCK != 0 || marker < 1 || marker > AES_BLOCK)
        return SEER_EPROTO;

    uint8_t *plain = malloc(ctlen ? ctlen : AES_BLOCK);
    if (plain == NULL)
        return SEER_ENOMEM;
    if (ctlen && !aes_cbc_oneshot(a->enc_key, a->keysize, (const uint8_t[16]){ 0 },
                                  ct, ctlen, plain, false)) {
        free(plain);
        return SEER_EPROTO;
    }
    if ((size_t)(marker - 1) > ctlen) { free(plain); return SEER_EPROTO; }
    size_t plainlen = ctlen - (size_t)(marker - 1);

    size_t payload_len = plainlen;
    if (a->has_mac) {
        if (plainlen < a->mac_size) { free(plain); return SEER_EPROTO; }
        payload_len = plainlen - a->mac_size;
        if (!mac_verify(a, plain, payload_len, plain + payload_len)) {
            free(plain);
            seer_log(SEER_LOG_ERROR, "ano: data integrity check failed");
            return SEER_EPROTO;
        }
    }

    uint8_t *p = malloc(payload_len ? payload_len : 1);
    if (p == NULL) { free(plain); return SEER_ENOMEM; }
    if (payload_len)
        memcpy(p, plain, payload_len);
    free(plain);
    *out = p;
    *outlen = payload_len;
    return SEER_OK;
}
