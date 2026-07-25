/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "auth.h"

#include "compat.h"

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------- primitives */

static const EVP_CIPHER *aes_cipher(size_t keylen)
{
    switch (keylen) {
    case 16: return EVP_aes_128_cbc();
    case 24: return EVP_aes_192_cbc();
    case 32: return EVP_aes_256_cbc();
    default: return NULL;
    }
}

/* AES-CBC with a zero IV and no padding (input a multiple of 16). enc != 0
 * encrypts. Key length picks AES-128/192/256. out must hold inlen bytes. */
static SeerStatus aes_cbc(int enc, const uint8_t *key, size_t keylen,
                          const uint8_t *in, size_t inlen, uint8_t *out)
{
    const EVP_CIPHER *cipher = aes_cipher(keylen);
    if (cipher == NULL || inlen % 16 != 0)
        return SEER_EPROTO;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return SEER_ENOMEM;

    const uint8_t iv[16] = { 0 };
    int ok, outl = 0, finl = 0;
    ok = enc ? EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)
             : EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
    if (ok) ok = EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (ok) ok = enc ? EVP_EncryptUpdate(ctx, out, &outl, in, (int)inlen)
                     : EVP_DecryptUpdate(ctx, out, &outl, in, (int)inlen);
    if (ok) ok = enc ? EVP_EncryptFinal_ex(ctx, out + outl, &finl)
                     : EVP_DecryptFinal_ex(ctx, out + outl, &finl);

    EVP_CIPHER_CTX_free(ctx);
    return ok ? SEER_OK : SEER_EPROTO;
}

/* DES moved to OpenSSL 3's legacy provider, which is not active by default.
 * Load it (plus default, since an explicit load suppresses implicit default
 * activation) the first time the 10g path needs DES. pthread_once makes this
 * race-free: concurrent first-time connects all block until the load completes,
 * so no thread can use DES before the provider is active. */
static pthread_once_t g_legacy_once = PTHREAD_ONCE_INIT;

static void load_legacy_provider(void)
{
    OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER_load(NULL, "default");
}

static void ensure_legacy_provider(void)
{
    pthread_once(&g_legacy_once, load_legacy_provider);
}

/* DES-CBC, zero IV, no padding (input a multiple of 8). */
static SeerStatus des_cbc(int enc, const uint8_t key[8],
                          const uint8_t *in, size_t inlen, uint8_t *out)
{
    if (inlen % 8 != 0)
        return SEER_EPROTO;
    ensure_legacy_provider();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return SEER_ENOMEM;

    const uint8_t iv[8] = { 0 };
    int ok, outl = 0, finl = 0;
    ok = enc ? EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv)
             : EVP_DecryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv);
    if (ok) ok = EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (ok) ok = enc ? EVP_EncryptUpdate(ctx, out, &outl, in, (int)inlen)
                     : EVP_DecryptUpdate(ctx, out, &outl, in, (int)inlen);
    if (ok) ok = enc ? EVP_EncryptFinal_ex(ctx, out + outl, &finl)
                     : EVP_DecryptFinal_ex(ctx, out + outl, &finl);

    EVP_CIPHER_CTX_free(ctx);
    return ok ? SEER_OK : SEER_EPROTO;
}

static void sha1_digest(const uint8_t *in, size_t n, uint8_t out[20])
{
    unsigned int olen = 0;
    EVP_Digest(in, n, out, &olen, EVP_sha1(), NULL);
}

static void sha512_digest(const uint8_t *in, size_t n, uint8_t out[64])
{
    unsigned int olen = 0;
    EVP_Digest(in, n, out, &olen, EVP_sha512(), NULL);
}

static void md5_digest(const uint8_t *in, size_t n, uint8_t out[16])
{
    unsigned int olen = 0;
    EVP_Digest(in, n, out, &olen, EVP_md5(), NULL);
}

static int pbkdf2_sha512(const uint8_t *pass, size_t passlen,
                         const uint8_t *salt, size_t saltlen,
                         int iter, uint8_t *out, size_t dklen)
{
    return PKCS5_PBKDF2_HMAC((const char *)pass, (int)passlen, salt, (int)saltlen,
                             iter, EVP_sha512(), (int)dklen, out);
}

/* Uppercase-hex `in` into `out` (2*n bytes, no NUL). */
static void hex_upper(const uint8_t *in, size_t n, uint8_t *out)
{
    static const char d[] = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = (uint8_t)d[in[i] >> 4];
        out[2 * i + 1] = (uint8_t)d[in[i] & 0x0F];
    }
}

/* pad1 (PROTOCOL.md §4.5): a fixed 16-byte 0x10 block, then the password with
 * PKCS#7 padding to the next 16-byte boundary. */
static size_t pad1_len(size_t plen)
{
    return 16 + plen + (16 - (plen % 16));
}
static void pad1_fill(const uint8_t *pw, size_t plen, uint8_t *out)
{
    size_t r = 16 - (plen % 16);
    memset(out, 0x10, 16);
    memcpy(out + 16, pw, plen);
    memset(out + 16 + plen, (int)r, r);
}

/* norm (DES verifier): each Unicode char -> 2 bytes (high 0, low = uppercased
 * code, or 0x3F '?' for > 255), then zero-pad to an 8-byte multiple. */
static size_t norm_into(const char *s, size_t n, uint8_t *out)
{
    size_t o = 0, i = 0;
    while (i < n) {
        unsigned char c = (unsigned char)s[i];
        uint32_t cp;
        if (c < 0x80) { cp = c; i += 1; }
        else if ((c >> 5) == 0x6 && i + 1 < n) {
            cp = ((uint32_t)(c & 0x1F) << 6) | (s[i + 1] & 0x3F); i += 2;
        } else if ((c >> 4) == 0xE && i + 2 < n) {
            cp = ((uint32_t)(c & 0x0F) << 12) | ((s[i + 1] & 0x3F) << 6) | (s[i + 2] & 0x3F); i += 3;
        } else if ((c >> 3) == 0x1E && i + 3 < n) {
            cp = ((uint32_t)(c & 0x07) << 18) | ((s[i + 1] & 0x3F) << 12)
               | ((s[i + 2] & 0x3F) << 6) | (s[i + 3] & 0x3F); i += 4;
        } else { cp = c; i += 1; }

        uint8_t lo;
        if (cp > 255)               lo = 0x3F;
        else if (cp >= 97 && cp <= 122) lo = (uint8_t)(cp - 32);
        else                        lo = (uint8_t)cp;
        out[o++] = 0;
        out[o++] = lo;
    }
    size_t pad = (8 - (o % 8)) % 8;
    memset(out + o, 0, pad);
    return o + pad;
}

void seer_des_verifier(const char *user, const char *password, uint8_t out[8])
{
    memset(out, 0, 8);
    size_t ul = strlen(user), pl = strlen(password);
    char   *cat = malloc(ul + pl + 1);
    uint8_t *nb = malloc(2 * (ul + pl) + 8 + 1);
    if (cat == NULL || nb == NULL) { free(cat); free(nb); return; }
    memcpy(cat, user, ul);
    memcpy(cat + ul, password, pl);
    size_t nlen = norm_into(cat, ul + pl, nb);
    free(cat);

    static const uint8_t k0[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    uint8_t *e1 = malloc(nlen ? nlen : 1);
    uint8_t *e2 = malloc(nlen ? nlen : 1);
    if (e1 != NULL && e2 != NULL && nlen >= 8 &&
        des_cbc(1, k0, nb, nlen, e1) == SEER_OK) {
        uint8_t inter[8];
        memcpy(inter, e1 + nlen - 8, 8);
        if (des_cbc(1, inter, nb, nlen, e2) == SEER_OK)
            memcpy(out, e2 + nlen - 8, 8);
    }
    free(nb); free(e1); free(e2);
}

/* O3LOGON (Oracle 9i / pre-10g thin auth): the server returns AUTH_SESSKEY - an
 * 8-byte session key DES-encrypted under the account's DES verifier. Decrypt it
 * with the verifier (`key_sess`, from seer_des_verifier) to recover the plaintext
 * session key, then DES-encrypt the zero-padded password under that key to form
 * AUTH_PASSWORD. Reuses the same DES-CBC (zero IV) primitive as the verifier.
 * Caller frees *auth_pass. */
SeerStatus seer_o3logon(const uint8_t *sess, size_t sess_len,
                        const uint8_t key_sess[8], const char *password,
                        uint8_t **auth_pass, size_t *auth_pass_len)
{
    if (sess == NULL || sess_len < 8 || sess_len % 8 != 0 || key_sess == NULL
        || password == NULL || auth_pass == NULL || auth_pass_len == NULL)
        return SEER_EPARAM;
    *auth_pass = NULL;
    *auth_pass_len = 0;

    uint8_t srv[256];
    if (sess_len > sizeof srv)
        return SEER_EPARAM;
    if (des_cbc(0, key_sess, sess, sess_len, srv) != SEER_OK)   /* -> plaintext session key */
        return SEER_EPROTO;

    size_t pl = strlen(password);
    size_t padlen = pl + ((8 - (pl % 8)) % 8);                  /* zero-pad to an 8-mult */
    if (padlen == 0)
        padlen = 8;
    uint8_t *pw  = calloc(padlen, 1);
    uint8_t *out = malloc(padlen);
    if (pw == NULL || out == NULL) { free(pw); free(out); return SEER_ENOMEM; }
    memcpy(pw, password, pl);

    SeerStatus st = des_cbc(1, srv, pw, padlen, out);           /* key = session key[0:8] */
    free(pw);
    if (st != SEER_OK) { free(out); return st; }
    *auth_pass     = out;
    *auth_pass_len = padlen;
    return SEER_OK;
}

void seer_o5logon_free(SeerO5Logon *o)
{
    if (o == NULL)
        return;
    free(o->auth_pass);
    free(o->auth_sess);
    free(o->speedy_key);
    memset(o, 0, sizeof *o);
}

/* --------------------------------------------------------------- the core */

SeerStatus seer_o5logon0(const uint8_t *sess, size_t sess_len,
                         const uint8_t *key_sess, size_t key_sess_len,
                         const uint8_t *derived_salt, size_t derived_salt_len,
                         const uint8_t *derived_key, size_t derived_key_len,
                         const uint8_t *cli_sess,
                         const char *password, int bits, SeerO5Logon *out)
{
    memset(out, 0, sizeof *out);
    if (sess_len % 16 != 0 || sess_len < 32)
        return SEER_EPROTO;

    SeerStatus st = SEER_OK;
    uint8_t *srv      = malloc(sess_len);
    uint8_t *cli      = malloc(sess_len);
    uint8_t *authsess = malloc(sess_len);
    uint8_t *cat      = NULL;
    uint8_t *pbuf     = NULL;
    uint8_t *authpass = NULL;
    uint8_t *speedy   = NULL;
    uint8_t *hexbuf   = NULL;
    if (srv == NULL || cli == NULL || authsess == NULL) {
        st = SEER_ENOMEM;
        goto done;
    }

    /* SrvSess = decrypt(server session key). */
    st = aes_cbc(0, key_sess, key_sess_len, sess, sess_len, srv);
    if (st != SEER_OK) goto done;

    /* Client session key: supplied (deterministic) or generated. The padded
     * form (40 random bytes + eight 0x08) mirrors a server key that carries
     * the same 0x08 trailer; otherwise sess_len random bytes. */
    if (cli_sess != NULL) {
        memcpy(cli, cli_sess, sess_len);
    } else {
        bool padded = (sess_len == 48);
        for (size_t i = 40; padded && i < 48; i++)
            if (srv[i] != 0x08) padded = false;
        if (padded) {
            if (RAND_bytes(cli, 40) != 1) { st = SEER_EIO; goto done; }
            memset(cli + 40, 0x08, 8);
        } else if (RAND_bytes(cli, (int)sess_len) != 1) {
            st = SEER_EIO; goto done;
        }
    }

    /* AuthSess = encrypt(client session key) under KeySess. */
    st = aes_cbc(1, key_sess, key_sess_len, cli, sess_len, authsess);
    if (st != SEER_OK) goto done;

    /* CatKey: XOR of the 16-byte (128) / 24-byte (192) middle slices for the
     * salt-less variants, or the full CliSess||SrvSess for 256-bit. */
    size_t catlen = 0;
    if (bits == 128 && derived_salt == NULL) {
        catlen = 16;
        cat = malloc(catlen);
        if (cat == NULL) { st = SEER_ENOMEM; goto done; }
        for (size_t i = 0; i < 16; i++) cat[i] = (uint8_t)(srv[16 + i] ^ cli[16 + i]);
    } else if (bits == 192 && derived_salt == NULL) {
        catlen = 24;
        cat = malloc(catlen);
        if (cat == NULL) { st = SEER_ENOMEM; goto done; }
        for (size_t i = 0; i < 24; i++) cat[i] = (uint8_t)(srv[16 + i] ^ cli[16 + i]);
    } else if (bits == 256) {
        catlen = 2 * sess_len;
        cat = malloc(catlen);
        if (cat == NULL) { st = SEER_ENOMEM; goto done; }
        memcpy(cat, cli, sess_len);
        memcpy(cat + sess_len, srv, sess_len);
    } else {
        st = SEER_ENOTIMPL;             /* e.g. salt-less 128 with a derived salt */
        goto done;
    }

    /* ConnKey: MD5 for the legacy variants, PBKDF2-SHA512 over the uppercase
     * hex of CatKey for 256-bit. */
    uint8_t conn[32];
    size_t  conn_len = 0;
    if (bits == 128) {
        md5_digest(cat, 16, conn);
        conn_len = 16;
    } else if (bits == 192) {
        uint8_t m1[16], m2[16];
        md5_digest(cat, 16, m1);
        md5_digest(cat + 16, 8, m2);
        memcpy(conn, m1, 16);
        memcpy(conn + 16, m2, 8);
        conn_len = 24;
    } else {                            /* 256 */
        hexbuf = malloc(2 * catlen);
        if (hexbuf == NULL) { st = SEER_ENOMEM; goto done; }
        hex_upper(cat, catlen, hexbuf);
        if (pbkdf2_sha512(hexbuf, 2 * catlen, derived_salt, derived_salt_len,
                          3, conn, 32) != 1) { st = SEER_EPROTO; goto done; }
        conn_len = 32;
    }

    /* AuthPass = AES-CBC(ConnKey) of pad1(password). */
    size_t plen = strlen(password);
    size_t pl   = pad1_len(plen);
    pbuf     = malloc(pl);
    authpass = malloc(pl);
    if (pbuf == NULL || authpass == NULL) { st = SEER_ENOMEM; goto done; }
    pad1_fill((const uint8_t *)password, plen, pbuf);
    st = aes_cbc(1, conn, conn_len, pbuf, pl, authpass);
    if (st != SEER_OK) goto done;

    /* AUTH_PBKDF2_SPEEDY_KEY = AES-CBC(ConnKey) of the derived key (12c). */
    size_t speedy_len = 0;
    if (derived_key != NULL) {
        if (derived_key_len % 16 != 0) { st = SEER_EPROTO; goto done; }
        speedy = malloc(derived_key_len);
        if (speedy == NULL) { st = SEER_ENOMEM; goto done; }
        st = aes_cbc(1, conn, conn_len, derived_key, derived_key_len, speedy);
        if (st != SEER_OK) goto done;
        speedy_len = derived_key_len;
    }

    out->auth_pass      = authpass;  authpass = NULL;
    out->auth_pass_len  = pl;
    out->auth_sess      = authsess;  authsess = NULL;
    out->auth_sess_len  = sess_len;
    out->speedy_key     = speedy;    speedy   = NULL;
    out->speedy_key_len = speedy_len;
    memcpy(out->conn_key, conn, conn_len);
    out->conn_key_len   = conn_len;

done:
    free(srv);
    free(cli);
    free(cat);
    free(pbuf);
    free(hexbuf);
    free(authpass);
    free(authsess);
    free(speedy);
    return st;
}

SeerStatus seer_o5logon0_192(const uint8_t *sess, size_t sess_len,
                             const uint8_t key_sess[24], const uint8_t *cli_sess,
                             const char *password, SeerO5Logon *out)
{
    return seer_o5logon0(sess, sess_len, key_sess, 24, NULL, 0, NULL, 0,
                         cli_sess, password, 192, out);
}

/* --------------------------------------------------------- the dispatcher */

SeerStatus seer_o5logon(const uint8_t *sess, size_t sess_len,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *derived_salt, size_t derived_salt_len,
                        const char *user, const char *password,
                        SeerO5Logon *out)
{
    memset(out, 0, sizeof *out);
    if (user == NULL) user = "";
    if (password == NULL) password = "";

    /* 10g: no salt at all - the account has only the legacy DES verifier. The
     * AES-128 key is that 8-byte verifier zero-padded to 16. */
    if (salt == NULL && derived_salt == NULL) {
        uint8_t ver[8];
        seer_des_verifier(user, password, ver);
        uint8_t key[16] = { 0 };
        memcpy(key, ver, 8);
        return seer_o5logon0(sess, sess_len, key, 16, NULL, 0, NULL, 0,
                             NULL, password, 128, out);
    }

    /* A derived salt without a verifier salt is a 128-bit DES-derived scheme
     * we do not implement. */
    if (salt == NULL)
        return SEER_ENOTIMPL;

    /* 11g: KeySess = SHA1(password ‖ salt) ‖ 0x00000000 (24-byte AES-192). */
    if (derived_salt == NULL) {
        size_t   plen = strlen(password);
        uint8_t *buf  = malloc(plen + salt_len);
        if (buf == NULL)
            return SEER_ENOMEM;
        memcpy(buf, password, plen);
        memcpy(buf + plen, salt, salt_len);
        uint8_t key[24] = { 0 };
        uint8_t h[20];
        sha1_digest(buf, plen + salt_len, h);
        free(buf);
        memcpy(key, h, 20);
        return seer_o5logon0(sess, sess_len, key, 24, NULL, 0, NULL, 0,
                             NULL, password, 192, out);
    }

    /* 12c: Data = PBKDF2-SHA512(password, salt ‖ "AUTH_PBKDF2_SPEEDY_KEY",
     * 4096); KeySess = SHA512(Data ‖ salt)[0:32]; DerivedKey = rand(16) ‖ Data. */
    static const char TAG[] = "AUTH_PBKDF2_SPEEDY_KEY";
    size_t   plen   = strlen(password);
    size_t   taglen = sizeof TAG - 1;
    uint8_t *saltbuf = malloc(salt_len + taglen);
    if (saltbuf == NULL)
        return SEER_ENOMEM;
    memcpy(saltbuf, salt, salt_len);
    memcpy(saltbuf + salt_len, TAG, taglen);

    uint8_t data[64];
    int rc = pbkdf2_sha512((const uint8_t *)password, plen,
                           saltbuf, salt_len + taglen, 4096, data, 64);
    free(saltbuf);
    if (rc != 1)
        return SEER_EPROTO;

    uint8_t *kbuf = malloc(64 + salt_len);
    if (kbuf == NULL)
        return SEER_ENOMEM;
    memcpy(kbuf, data, 64);
    memcpy(kbuf + 64, salt, salt_len);
    uint8_t h512[64];
    sha512_digest(kbuf, 64 + salt_len, h512);
    free(kbuf);

    uint8_t key[32];
    memcpy(key, h512, 32);

    uint8_t dkey[80];
    if (RAND_bytes(dkey, 16) != 1)
        return SEER_EIO;
    memcpy(dkey + 16, data, 64);

    return seer_o5logon0(sess, sess_len, key, 32, derived_salt, derived_salt_len,
                         dkey, 80, NULL, password, 256, out);
}

bool seer_o5logon_validate(const uint8_t *resp, size_t resp_len,
                           const uint8_t *conn_key, size_t conn_key_len)
{
    if (aes_cipher(conn_key_len) == NULL || resp_len == 0 || resp_len % 16 != 0)
        return false;

    uint8_t *hay = malloc(resp_len);
    if (hay == NULL)
        return false;
    bool ok = false;
    if (aes_cbc(0, conn_key, conn_key_len, resp, resp_len, hay) == SEER_OK)
        ok = seer_memmem(hay, resp_len, "SERVER_TO_CLIENT", 16) != NULL;
    free(hay);
    return ok;
}
