/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "transport.h"

#include "log.h"

#include <stdbool.h>
#include "netcompat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/* OpenSSL writes to the socket itself, so MSG_NOSIGNAL can't reach those
 * writes; a peer reset would raise SIGPIPE and kill the host application.
 * Where SO_NOSIGPIPE exists (macOS/BSD) the socket option covers it. Elsewhere
 * block SIGPIPE on this thread around OpenSSL's writes and swallow one raised
 * meanwhile (the approach libcurl takes), so the write just fails with EPIPE. */
#if !defined(_WIN32) && !defined(SO_NOSIGPIPE)
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>

typedef struct {
  sigset_t old;
  bool had_pending;
} SigpipeGuard;

static void sigpipe_block(SigpipeGuard *g)
{
  sigset_t set, pend;
  sigemptyset(&set);
  sigaddset(&set, SIGPIPE);
  sigemptyset(&pend);
  sigpending(&pend);
  g->had_pending = sigismember(&pend, SIGPIPE) == 1;
  pthread_sigmask(SIG_BLOCK, &set, &g->old);
}

static void sigpipe_restore(SigpipeGuard *g)
{
  if (!g->had_pending) {
    sigset_t set, pend;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    sigemptyset(&pend);
    sigpending(&pend);
    if (sigismember(&pend, SIGPIPE) == 1) {
      const struct timespec zero = {0, 0};
      while (sigtimedwait(&set, NULL, &zero) < 0 && errno == EINTR)
        ;
    }
  }
  pthread_sigmask(SIG_SETMASK, &g->old, NULL);
}
#else
typedef int SigpipeGuard;
static void sigpipe_block(SigpipeGuard *g)
{
  (void)g;
}
static void sigpipe_restore(SigpipeGuard *g)
{
  (void)g;
}
#endif

#define DEFAULT_TIMEOUT_MS 30000

struct SeerTransport {
  seer_socket_t fd;
  SSL *ssl; /* non-NULL once TLS is established */
  SSL_CTX *ctx;
  bool large_frames; /* 4-byte packet length (§ ver >= 315, #155) */
};

void seer_transport_set_large_frames(SeerTransport *t, int on)
{
  if (t != NULL)
    t->large_frames = (on != 0);
}

int seer_transport_large_frames(const SeerTransport *t)
{
  return t != NULL && t->large_frames;
}

void seer_transport_set_io_timeout(SeerTransport *t, int timeout_ms)
{
  if (t == NULL)
    return;
  if (timeout_ms < 0)
    timeout_ms = DEFAULT_TIMEOUT_MS;
  seer_sock_set_io_timeout(t->fd, timeout_ms);
}

int seer_transport_wait_readable(SeerTransport *t, int timeout_ms)
{
  if (t == NULL)
    return -1;
  if (t->ssl != NULL && SSL_pending(t->ssl) > 0)
    return 1; /* already decrypted, the socket may be quiet */
  seer_pollfd pfd = {.fd = t->fd, .events = POLLIN};
  int rc;
  do {
    rc = seer_poll(&pfd, 1, timeout_ms);
  } while (rc < 0 && seer_sock_errno() == SEER_EINTR);
  return rc > 0 ? 1 : (rc == 0 ? 0 : -1);
}

/* The most recent OpenSSL error string (for logging), or a fallback. */
static const char *ssl_err(void)
{
  unsigned long e = ERR_peek_last_error();
  return e ? ERR_error_string(e, NULL) : "TLS error";
}

/* Restore blocking mode and arm SO_RCVTIMEO / SO_SNDTIMEO on the socket. */
static void arm_io_timeout(seer_socket_t fd, int timeout_ms)
{
  (void)seer_sock_set_nonblocking(fd, 0);
  seer_sock_set_io_timeout(fd, timeout_ms);
}

/* Non-blocking connect to one resolved address, bounded by timeout_ms.
 * Returns a connected socket or SEER_INVALID_SOCKET. */
static seer_socket_t connect_one(const struct addrinfo *ai, int timeout_ms)
{
  seer_socket_t fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (fd == SEER_INVALID_SOCKET)
    return SEER_INVALID_SOCKET;
  seer_sock_nosigpipe(fd);

  if (seer_sock_set_nonblocking(fd, 1) != 0) {
    seer_closesocket(fd);
    return SEER_INVALID_SOCKET;
  }

  int rc;
  do {
    rc = connect(fd, ai->ai_addr, (socklen_t)ai->ai_addrlen);
  } while (rc < 0 && seer_sock_errno() == SEER_EINTR);

  if (rc < 0 && seer_sock_errno() == SEER_EINPROGRESS) {
    seer_pollfd pfd = {.fd = fd, .events = POLLOUT};
    do {
      rc = seer_poll(&pfd, 1, timeout_ms);
    } while (rc < 0 && seer_sock_errno() == SEER_EINTR);

    if (rc <= 0) { /* timed out (0) or poll error (<0) */
      seer_closesocket(fd);
      return SEER_INVALID_SOCKET;
    }
    int err = 0;
    if (seer_sock_so_error(fd, &err) != 0 || err != 0) {
      seer_closesocket(fd);
      return SEER_INVALID_SOCKET;
    }
  } else if (rc < 0) {
    seer_closesocket(fd);
    return SEER_INVALID_SOCKET;
  }

  arm_io_timeout(fd, timeout_ms);
  return fd;
}

SeerStatus seer_transport_connect(const char *host, uint16_t port, int timeout_ms,
                                  SeerTransport **out)
{
  if (host == NULL || out == NULL)
    return SEER_EPARAM;
  *out = NULL;
  if (timeout_ms <= 0)
    timeout_ms = DEFAULT_TIMEOUT_MS;

  if (seer_net_init() != 0) {
    seer_log(SEER_LOG_ERROR, "transport: network stack init failed");
    return SEER_EIO;
  }

  char portstr[6];
  snprintf(portstr, sizeof portstr, "%u", (unsigned)port);

  struct addrinfo hints = {
      .ai_family = AF_UNSPEC,
      .ai_socktype = SOCK_STREAM,
  };
  struct addrinfo *res = NULL;
  int gai = getaddrinfo(host, portstr, &hints, &res);
  if (gai != 0) {
    seer_log(SEER_LOG_ERROR, "transport: resolve %s:%u failed: %s", host, (unsigned)port,
             gai_strerror(gai));
    return SEER_EIO;
  }

  seer_socket_t fd = SEER_INVALID_SOCKET;
  for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
    fd = connect_one(ai, timeout_ms);
    if (fd != SEER_INVALID_SOCKET)
      break;
  }
  freeaddrinfo(res);

  if (fd == SEER_INVALID_SOCKET) {
    seer_log(SEER_LOG_ERROR, "transport: connect to %s:%u failed", host, (unsigned)port);
    return SEER_EIO;
  }

  SeerTransport *t = calloc(1, sizeof *t);
  if (t == NULL) {
    seer_closesocket(fd);
    return SEER_ENOMEM;
  }
  t->fd = fd;
  *out = t;
  seer_log(SEER_LOG_INFO, "transport: connected to %s:%u", host, (unsigned)port);
  return SEER_OK;
}

SeerStatus seer_transport_start_tls(SeerTransport *t, const char *sni_host, const char *ca_file,
                                    int verify)
{
  if (t == NULL)
    return SEER_EPARAM;
  if (t->ssl != NULL)
    return SEER_OK; /* already wrapped */

  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (ctx == NULL) {
    seer_log(SEER_LOG_ERROR, "transport: SSL_CTX_new failed: %s", ssl_err());
    return SEER_EIO;
  }
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

  if (verify) {
    if (ca_file != NULL) {
      if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
        seer_log(SEER_LOG_ERROR, "transport: cannot load CA %s: %s", ca_file, ssl_err());
        SSL_CTX_free(ctx);
        return SEER_EPARAM;
      }
    } else {
      SSL_CTX_set_default_verify_paths(ctx);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  } else {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  }

  SSL *ssl = SSL_new(ctx);
  if (ssl == NULL) {
    seer_log(SEER_LOG_ERROR, "transport: SSL_new failed: %s", ssl_err());
    SSL_CTX_free(ctx);
    return SEER_EIO;
  }
  SSL_set_fd(ssl, (int)t->fd);
  if (sni_host != NULL && *sni_host) {
    SSL_set_tlsext_host_name(ssl, sni_host); /* SNI */
    if (verify)
      SSL_set1_host(ssl, sni_host); /* hostname verification */
  }

  int rc;
  SigpipeGuard g;
  for (;;) {
    sigpipe_block(&g);
    rc = SSL_connect(ssl);
    sigpipe_restore(&g);
    if (rc == 1)
      break;
    int e = SSL_get_error(ssl, rc);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
      continue; /* blocking fd: retry */
    seer_log(SEER_LOG_ERROR, "transport: TLS handshake failed: %s", ssl_err());
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return SEER_EIO;
  }
  t->ssl = ssl;
  t->ctx = ctx;
  seer_log(SEER_LOG_INFO, "transport: TLS established (%s, %s)", SSL_get_version(ssl),
           SSL_get_cipher(ssl));
  return SEER_OK;
}

void seer_transport_close(SeerTransport *t)
{
  if (t == NULL)
    return;
  if (t->ssl != NULL) {
    SigpipeGuard g;
    sigpipe_block(&g);
    SSL_shutdown(t->ssl);
    sigpipe_restore(&g);
    SSL_free(t->ssl);
  }
  if (t->ctx != NULL)
    SSL_CTX_free(t->ctx);
  if (t->fd != SEER_INVALID_SOCKET)
    seer_closesocket(t->fd);
  free(t);
}

SeerStatus seer_transport_write_all(SeerTransport *t, const void *buf, size_t len)
{
  if (t == NULL || (buf == NULL && len > 0))
    return SEER_EPARAM;

  const uint8_t *p = buf;
  size_t off = 0;
  while (off < len) {
    if (t->ssl != NULL) {
      SigpipeGuard g;
      sigpipe_block(&g);
      int n = SSL_write(t->ssl, p + off, (int)(len - off));
      sigpipe_restore(&g);
      if (n <= 0) {
        int e = SSL_get_error(t->ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
          continue;
        seer_log(SEER_LOG_ERROR, "transport: TLS write failed: %s", ssl_err());
        return SEER_EIO;
      }
      off += (size_t)n;
      continue;
    }
    ptrdiff_t n = seer_sock_send(t->fd, p + off, len - off);
    if (n < 0) {
      if (seer_sock_errno() == SEER_EINTR)
        continue;
      seer_log(SEER_LOG_ERROR, "transport: write failed (error %d)", seer_sock_errno());
      return SEER_EIO;
    }
    off += (size_t)n;
  }
  return SEER_OK;
}

SeerStatus seer_transport_read_full(SeerTransport *t, void *buf, size_t len)
{
  if (t == NULL || (buf == NULL && len > 0))
    return SEER_EPARAM;

  uint8_t *p = buf;
  size_t off = 0;
  while (off < len) {
    if (t->ssl != NULL) {
      int n = SSL_read(t->ssl, p + off, (int)(len - off));
      if (n <= 0) {
        int e = SSL_get_error(t->ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
          continue;
        if (e == SSL_ERROR_ZERO_RETURN)
          seer_log(SEER_LOG_ERROR,
                   "transport: TLS closed by peer "
                   "(wanted %zu bytes, got %zu)",
                   len, off);
        else
          seer_log(SEER_LOG_ERROR, "transport: TLS read failed: %s", ssl_err());
        return SEER_EIO;
      }
      off += (size_t)n;
      continue;
    }
    ptrdiff_t n = seer_sock_recv(t->fd, p + off, len - off);
    if (n < 0) {
      if (seer_sock_errno() == SEER_EINTR)
        continue;
      seer_log(SEER_LOG_ERROR, "transport: read failed (error %d)", seer_sock_errno());
      return SEER_EIO;
    }
    if (n == 0) {
      seer_log(SEER_LOG_ERROR,
               "transport: connection closed by peer "
               "(wanted %zu bytes, got %zu)",
               len, off);
      return SEER_EIO;
    }
    off += (size_t)n;
  }
  return SEER_OK;
}
