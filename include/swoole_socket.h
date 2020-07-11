/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "buffer.h"

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK O_NONBLOCK
#endif

// OS Feature
#if defined(HAVE_KQUEUE) || !defined(HAVE_SENDFILE)
int swoole_sendfile(int out_fd, int in_fd, off_t *offset, size_t size);
#else
#include <sys/sendfile.h>
#define swoole_sendfile(out_fd, in_fd, offset, limit) sendfile(out_fd, in_fd, offset, limit)
#endif

struct swTask_sendfile {
    char *filename;
    uint16_t name_len;
    int fd;
    size_t length;
    off_t offset;
};

struct swSendFile_request {
    off_t offset;
    size_t length;
    char filename[0];
};

struct swSocketAddress {
    union {
        struct sockaddr ss;
        struct sockaddr_in inet_v4;
        struct sockaddr_in6 inet_v6;
        struct sockaddr_un un;
    } addr;
    socklen_t len;
};

struct swSocket {
    int fd;
    enum swFd_type fdtype;
    enum swSocket_type socket_type;
    int events;

    uchar removed : 1;
    uchar nonblock : 1;
    uchar cloexec : 1;
    uchar direct_send : 1;
#ifdef SW_USE_OPENSSL
    uchar ssl_send : 1;
    uchar ssl_want_read : 1;
    uchar ssl_want_write : 1;
    uchar ssl_renegotiation : 1;
    uchar ssl_handshake_buffer_set : 1;
    uchar ssl_quiet_shutdown : 1;
#ifdef SW_SUPPORT_DTLS
    uchar dtls : 1;
#endif
#endif
    uchar dontwait : 1;
    uchar close_wait : 1;
    uchar send_wait : 1;
    uchar tcp_nopush : 1;
    uchar tcp_nodelay : 1;
    uchar skip_recv : 1;
    uchar recv_wait : 1;
    uchar event_hup : 1;

    /**
     * memory buffer size;
     */
    uint32_t buffer_size;
    uint32_t chunk_size;

    void *object;

#ifdef SW_USE_OPENSSL
    SSL *ssl;
    uint32_t ssl_state;
#endif

    swSocketAddress info;

    swBuffer *out_buffer;
    swBuffer *in_buffer;
    swString *recv_buffer;

#ifdef SW_DEBUG
    size_t total_recv_bytes;
    size_t total_send_bytes;
#endif
};

int swSocket_set_timeout(swSocket *sock, double timeout);
swSocket *swSocket_create_server(enum swSocket_type type, const char *address, int port, int backlog);
static sw_inline int swSocket_is_dgram(uint8_t type) {
    return (type == SW_SOCK_UDP || type == SW_SOCK_UDP6 || type == SW_SOCK_UNIX_DGRAM);
}

static sw_inline int swSocket_is_stream(uint8_t type) {
    return (type == SW_SOCK_TCP || type == SW_SOCK_TCP6 || type == SW_SOCK_UNIX_STREAM);
}

swSocket *swSocket_new(int fd, enum swFd_type type);
void swSocket_free(swSocket *sock);
int swSocket_create(enum swSocket_type type, uchar nonblock, uchar cloexec);
int swSocket_bind(swSocket *sock, const char *host, int *port);
swSocket *swSocket_accept(swSocket *server_socket, swSocketAddress *sa);
int swSocket_wait(int fd, int timeout_ms, int events);
int swSocket_wait_multi(int *list_of_fd, int n_fd, int timeout_ms, int events);
void swSocket_clean(int fd);
ssize_t swSocket_sendto_blocking(
    int fd, const void *buf, size_t n, int flag, struct sockaddr *addr, socklen_t addr_len);
int swSocket_set_buffer_size(swSocket *sock, uint32_t buffer_size);
ssize_t swSocket_udp_sendto(int server_sock, const char *dst_ip, int dst_port, const char *data, uint32_t len);
ssize_t swSocket_udp_sendto6(int server_sock, const char *dst_ip, int dst_port, const char *data, uint32_t len);
ssize_t swSocket_unix_sendto(int server_sock, const char *dst_path, const char *data, uint32_t len);
int swSocket_sendfile_sync(int sock, const char *filename, off_t offset, size_t length, double timeout);
ssize_t swSocket_write_blocking(swSocket *sock, const void *__data, size_t __len);
ssize_t swSocket_recv_blocking(swSocket *sock, void *__data, size_t __len, int flags);

static sw_inline int swSocket_error(int err) {
    switch (err) {
    case EFAULT:
        abort();
        return SW_ERROR;
    case EBADF:
    case ECONNRESET:
#ifdef __CYGWIN__
    case ECONNABORTED:
#endif
    case EPIPE:
    case ENOTCONN:
    case ETIMEDOUT:
    case ECONNREFUSED:
    case ENETDOWN:
    case ENETUNREACH:
    case EHOSTDOWN:
    case EHOSTUNREACH:
    case SW_ERROR_SSL_BAD_CLIENT:
    case SW_ERROR_SSL_RESET:
        return SW_CLOSE;
    case EAGAIN:
#ifdef HAVE_KQUEUE
    case ENOBUFS:
#endif
    case 0:
        return SW_WAIT;
    default:
        return SW_ERROR;
    }
}

ssize_t swSocket_recv(swSocket *conn, void *__buf, size_t __n, int __flags);
ssize_t swSocket_send(swSocket *conn, const void *__buf, size_t __n, int __flags);
ssize_t swSocket_peek(swSocket *conn, void *__buf, size_t __n, int __flags);

static sw_inline int swSocket_set_nonblock(swSocket *sock) {
    if (swoole_fcntl_set_option(sock->fd, 1, -1) < 0) {
        return SW_ERR;
    } else {
        sock->nonblock = 1;
        return SW_OK;
    }
}

static sw_inline int swSocket_get_domain_and_type(enum swSocket_type type, int *sock_domain, int *sock_type) {
    switch (type) {
    case SW_SOCK_TCP6:
        *sock_domain = AF_INET6;
        *sock_type = SOCK_STREAM;
        break;
    case SW_SOCK_UNIX_STREAM:
        *sock_domain = AF_UNIX;
        *sock_type = SOCK_STREAM;
        break;
    case SW_SOCK_UDP:
        *sock_domain = AF_INET;
        *sock_type = SOCK_DGRAM;
        break;
    case SW_SOCK_UDP6:
        *sock_domain = AF_INET6;
        *sock_type = SOCK_DGRAM;
        break;
    case SW_SOCK_UNIX_DGRAM:
        *sock_domain = AF_UNIX;
        *sock_type = SOCK_DGRAM;
        break;
    case SW_SOCK_TCP:
        *sock_domain = AF_INET;
        *sock_type = SOCK_STREAM;
        break;
    default:
        return SW_ERR;
    }

    return SW_OK;
}

static sw_inline int swSocket_set_block(swSocket *sock) {
    if (swoole_fcntl_set_option(sock->fd, 0, -1) < 0) {
        return SW_ERR;
    } else {
        sock->nonblock = 0;
        return SW_OK;
    }
}

int swSocket_buffer_send(swSocket *conn);

int swSocket_sendfile(swSocket *conn, const char *filename, off_t offset, size_t length);
int swSocket_onSendfile(swSocket *conn, swBuffer_chunk *chunk);
void swSocket_sendfile_destructor(swBuffer_chunk *chunk);
const char *swSocket_get_ip(enum swSocket_type socket_type, swSocketAddress *info);
int swSocket_get_port(enum swSocket_type socket_type, swSocketAddress *info);

#ifdef TCP_CORK
#define HAVE_TCP_NOPUSH
static sw_inline int swSocket_tcp_nopush(int sock, int nopush) {
    return setsockopt(sock, IPPROTO_TCP, TCP_CORK, (const void *) &nopush, sizeof(int));
}
#else
#define swSocket_tcp_nopush(sock, nopush)
#endif
