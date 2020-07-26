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

namespace swoole { namespace network {

struct Address {
    union {
        struct sockaddr ss;
        struct sockaddr_in inet_v4;
        struct sockaddr_in6 inet_v6;
        struct sockaddr_un un;
    } addr;
    socklen_t len;
    enum swSocket_type type;

    bool assign(enum swSocket_type _type, const char *_host, int _port);
    const char *get_ip();
    int get_port();
};

struct Socket {
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

    Address info;

    swBuffer *out_buffer;
    swBuffer *in_buffer;
    swString *recv_buffer;

#ifdef SW_DEBUG
    size_t total_recv_bytes;
    size_t total_send_bytes;
#endif

    /**
     * for reactor
     */
    int handle_send();
    int handle_sendfile(swBuffer_chunk *chunk);
    /**
     * socket option
     */
    int set_buffer_size(uint32_t _buffer_size);
    int set_timeout(double timeout);

    inline int set_nonblock() {
        if (swoole_fcntl_set_option(fd, 1, -1) < 0) {
            return SW_ERR;
        } else {
            nonblock = 1;
            return SW_OK;
        }
    }
    
    inline int set_block() {
        if (swoole_fcntl_set_option(fd, 0, -1) < 0) {
            return SW_ERR;
        } else {
            nonblock = 0;
            return SW_OK;
        }
    }

    inline int set_tcp_nopush(int nopush) {
        tcp_nopush = nopush;
#ifdef TCP_CORK
#define HAVE_TCP_NOPUSH
        return setsockopt(fd, IPPROTO_TCP, TCP_CORK, (const void *) &nopush, sizeof(int));
#else
        return 0;
#endif
    }
    /**
     * socket io operation
     */ 
    int sendfile(const char *filename, off_t offset, size_t length);
    ssize_t recv(void *__buf, size_t __n, int __flags);
    ssize_t send(const void *__buf, size_t __n, int __flags);
    ssize_t peek(void *__buf, size_t __n, int __flags);
    swSocket *accept();
    int bind(const char *host, int *port);
    ssize_t send_blocking(const void *__data, size_t __len);
    ssize_t recv_blocking(void *__data, size_t __len, int flags);
    int sendfile_blocking(const char *filename, off_t offset, size_t length, double timeout);
    inline int connect(const Address &sa) {
        return ::connect(fd, (struct sockaddr *) &sa.addr, sa.len);
    }
    void free();
};
}
network::Socket *make_socket(int fd, enum swFd_type type);
network::Socket *make_socket(enum swSocket_type socktype, enum swFd_type fdtype, int flags);
network::Socket *make_server_socket(enum swSocket_type type, const char *address, int port, int backlog = SW_BACKLOG);
}

static sw_inline int swSocket_is_dgram(uint8_t type) {
    return (type == SW_SOCK_UDP || type == SW_SOCK_UDP6 || type == SW_SOCK_UNIX_DGRAM);
}

static sw_inline int swSocket_is_stream(uint8_t type) {
    return (type == SW_SOCK_TCP || type == SW_SOCK_TCP6 || type == SW_SOCK_UNIX_STREAM);
}

int swSocket_wait(int fd, int timeout_ms, int events);
int swSocket_wait_multi(int *list_of_fd, int n_fd, int timeout_ms, int events);
void swSocket_clean(int fd);
ssize_t swSocket_sendto_blocking(
    int fd, const void *buf, size_t n, int flag, struct sockaddr *addr, socklen_t addr_len);

ssize_t swSocket_udp_sendto(int server_sock, const char *dst_ip, int dst_port, const char *data, uint32_t len);
ssize_t swSocket_udp_sendto6(int server_sock, const char *dst_ip, int dst_port, const char *data, uint32_t len);
ssize_t swSocket_unix_sendto(int server_sock, const char *dst_path, const char *data, uint32_t len);

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

