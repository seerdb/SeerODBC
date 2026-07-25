/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_NETCOMPAT_H
#define SEER_NETCOMPAT_H

/*
 * Thin portability layer over the sockets API. POSIX (Linux/macOS/BSD) exposes
 * BSD sockets as file descriptors reachable through <sys/socket.h> & friends;
 * Windows exposes them as opaque SOCKET handles through Winsock, where they are
 * NOT file descriptors - read()/write()/close()/fcntl()/poll() do not apply.
 *
 * The core touches the network in a few places (transport.c for the socket
 * lifecycle, ttc.c and session.c for gethostname()), so this header keeps the
 * platform #ifdef in one spot and lets those callers stay readable. recv()/send()
 * work on
 * TCP sockets on every platform, so we standardise on them instead of read/write.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>

typedef SOCKET seer_socket_t;
#  define SEER_INVALID_SOCKET  INVALID_SOCKET
#  define seer_closesocket     closesocket
#  define seer_poll            WSAPoll
typedef WSAPOLLFD seer_pollfd;

/* Nonblocking connect() reports "in progress" as WSAEWOULDBLOCK, not EINPROGRESS. */
#  define SEER_EINTR           WSAEINTR
#  define SEER_EINPROGRESS     WSAEWOULDBLOCK

static inline int seer_sock_errno(void) { return WSAGetLastError(); }

#else /* POSIX */
#  include <errno.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <sys/types.h>
#  include <unistd.h>

typedef int seer_socket_t;
#  define SEER_INVALID_SOCKET  (-1)
#  define seer_closesocket     close
#  define seer_poll            poll
typedef struct pollfd seer_pollfd;

#  define SEER_EINTR           EINTR
#  define SEER_EINPROGRESS     EINPROGRESS

static inline int seer_sock_errno(void) { return errno; }
#endif

/*
 * One-time network-stack initialisation: WSAStartup() on Windows (idempotent via
 * InitOnceExecuteOnce), a no-op returning 0 on POSIX. Call before the first
 * getaddrinfo()/socket()/gethostname(). Returns 0 on success, -1 on failure.
 */
int seer_net_init(void);

/* recv/send on a connected TCP socket, with a uniform signed return on both
 * platforms (Winsock's int, POSIX's ssize_t). Negative means error. */
static inline ptrdiff_t seer_sock_recv(seer_socket_t s, void *buf, size_t len)
{
#ifdef _WIN32
    return recv(s, buf, (int)len, 0);
#else
    return recv(s, buf, len, 0);
#endif
}

static inline ptrdiff_t seer_sock_send(seer_socket_t s, const void *buf, size_t len)
{
#ifdef _WIN32
    return send(s, (const char *)buf, (int)len, 0);
#else
    return send(s, buf, len, 0);
#endif
}

/* Switch a socket between blocking and nonblocking. Returns 0 / -1. */
static inline int seer_sock_set_nonblocking(seer_socket_t s, int nonblocking)
{
#ifdef _WIN32
    u_long v = nonblocking ? 1u : 0u;
    return ioctlsocket(s, FIONBIO, &v) == 0 ? 0 : -1;
#else
    int fl = fcntl(s, F_GETFL, 0);
    if (fl < 0)
        return -1;
    fl = nonblocking ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK);
    return fcntl(s, F_SETFL, fl) < 0 ? -1 : 0;
#endif
}

/* Arm SO_RCVTIMEO / SO_SNDTIMEO. Windows takes a DWORD of milliseconds; POSIX a
 * struct timeval. */
static inline void seer_sock_set_io_timeout(seer_socket_t s, int timeout_ms)
{
#ifdef _WIN32
    DWORD tv = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof tv);
#else
    struct timeval tv = {
        .tv_sec  = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
#endif
}

/* Read the pending socket error (SO_ERROR) into *out. Returns 0 / -1. */
static inline int seer_sock_so_error(seer_socket_t s, int *out)
{
    int err = 0;
#ifdef _WIN32
    int len = (int)sizeof err;
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &len) != 0)
        return -1;
#else
    socklen_t len = sizeof err;
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len) != 0)
        return -1;
#endif
    *out = err;
    return 0;
}

#endif /* SEER_NETCOMPAT_H */
