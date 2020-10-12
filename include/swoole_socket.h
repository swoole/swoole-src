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
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <string>
#include <vector>

#include "swoole_buffer.h"

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

namespace swoole {
namespace network {

struct GetaddrinfoRequest {
    const char *hostname;
    const char *service;
    int family;
    int socktype;
    int protocol;
    int error;
    void *result;
    int count;

    void parse_result(std::vector<std::string> &retval);
};

struct SendfileTask {
    off_t offset;
    size_t length;
    char filename[0];
};

struct SendfileRequest {
    char *filename;
    uint16_t name_len;
    int fd;
    size_t length;
    off_t offset;
};

struct Address {
    union {
        struct sockaddr ss;
        struct sockaddr_in inet_v4;
        struct sockaddr_in6 inet_v6;
        struct sockaddr_un un;
    } addr;
    socklen_t len;
    enum swSocket_type type;

    Address() = default;

    Address(enum swSocket_type _type, const std::string &_host, int _port) {
        if (!assign(_type, _host, _port)) {
            throw std::bad_exception();
        }
    }

    bool assign(enum swSocket_type _type, const std::string &_host, int _port);
    const char *get_ip() {
        return get_addr();
    }
    int get_port();
    const char *get_addr();

    static bool verify_ip(int __af, const std::string &str) {
        char tmp_address[INET6_ADDRSTRLEN];
        return inet_pton(__af, str.c_str(), tmp_address) != -1;
    }
};

struct Socket {
    static double default_dns_timeout;
    static double default_connect_timeout;
    static double default_read_timeout;
    static double default_write_timeout;
    static uint32_t default_buffer_size;

    int fd;
    enum swFd_type fd_type;
    enum swSocket_type socket_type;
    int events;
    bool enable_tcp_nodelay;

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
    double recv_timeout_ = default_read_timeout;
    double send_timeout_ = default_write_timeout;

    double last_received_time;
    double last_sent_time;

    Buffer *out_buffer;
    Buffer *in_buffer;
    String *recv_buffer;

    TimerNode *recv_timer;
    TimerNode *send_timer;

    size_t total_recv_bytes;
    size_t total_send_bytes;

    /**
     * for reactor
     */
    int handle_send();
    int handle_sendfile();
    /**
     * socket option
     */
    bool set_buffer_size(uint32_t _buffer_size);
    bool set_recv_buffer_size(uint32_t _buffer_size);
    bool set_send_buffer_size(uint32_t _buffer_size);
    bool set_timeout(double timeout);
    bool set_recv_timeout(double timeout);
    bool set_send_timeout(double timeout);

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

    inline int set_fd_option(int blocking, int cloexec) {
        return swoole_fcntl_set_option(fd, blocking, cloexec);
    }

    inline int set_option(int level, int optname, int optval) {
        return setsockopt(fd, level, optname, &optval, sizeof(optval));
    }

    inline int set_option(int level, int optname, const void *optval, socklen_t optlen) {
        return setsockopt(fd, level, optname, optval, optlen);
    }

    inline int get_option(int level, int optname, void *optval, socklen_t *optlen) {
        return getsockopt(fd, level, optname, optval, optlen);
    }

    inline int get_option(int level, int optname, int *optval) {
        socklen_t optlen = sizeof(*optval);
        return get_option(level, optname, optval, &optlen);
    }

    inline int get_name(Address *sa) {
        sa->len = sizeof(sa->addr);
        return getsockname(fd, &sa->addr.ss, &sa->len);
    }

    inline int set_tcp_nopush(int nopush) {
#ifdef TCP_CORK
        if (set_option(IPPROTO_TCP, TCP_CORK, nopush) == SW_ERR) {
            return -1;
        } else {
            tcp_nopush = nopush;
            return 0;
        }
#else
        return -1;
#endif
    }

    int set_reuse_addr(int enable = 1) {
        return set_option(SOL_SOCKET, SO_REUSEADDR, enable);
    }

    int set_reuse_port(int enable = 1) {
#ifdef SO_REUSEPORT
        return set_option(SOL_SOCKET, SO_REUSEPORT, enable);
#endif
        return -1;
    }

    int set_tcp_nodelay(int nodelay = 1)  {
        if (set_option(IPPROTO_TCP, TCP_NODELAY, nodelay) == SW_ERR) {
            return -1;
        } else {
            tcp_nodelay = nodelay;
            return 0;
        }
    }

    /**
     * socket io operation
     */
    int sendfile(const char *filename, off_t offset, size_t length);
    ssize_t recv(void *__buf, size_t __n, int __flags);
    ssize_t send(const void *__buf, size_t __n, int __flags);
    ssize_t peek(void *__buf, size_t __n, int __flags);
    Socket *accept();
    int bind(const std::string &_host, int *port);
    int bind(const Address &sa) {
        return ::bind(fd, &sa.addr.ss, sizeof(sa.addr.ss));
    }
    int listen(int backlog = 0) {
        return ::listen(fd, backlog <= 0 ? SW_BACKLOG : backlog);
    }
    void clean();
    ssize_t send_blocking(const void *__data, size_t __len);
    ssize_t recv_blocking(void *__data, size_t __len, int flags);
    int sendfile_blocking(const char *filename, off_t offset, size_t length, double timeout);

    inline int connect(const Address &sa) {
        return ::connect(fd, &sa.addr.ss, sa.len);
    }

    inline int connect(const Address *sa) {
        return ::connect(fd, &sa->addr.ss, sa->len);
    }

    inline int connect(const std::string &host, int port) {
        Address addr;
        addr.assign(socket_type, host, port);
        return connect(addr);
    }

    inline ssize_t recvfrom(char *__buf, size_t __len, int flags, Address *sa) {
        sa->len = sizeof(sa->addr);
        return ::recvfrom(fd, __buf, __len, flags, &sa->addr.ss, &sa->len);
    }

    inline bool cork() {
        if (tcp_nopush) {
            return false;
        }
        if (set_tcp_nopush(1) < 0) {
            swSysWarn("set_tcp_nopush(fd=%d, ON) failed", fd);
            return false;
        }
        // Need to turn off tcp nodelay when using nopush
        if (tcp_nodelay && set_tcp_nodelay(0) != 0) {
            swSysWarn("set_tcp_nodelay(fd=%d, OFF) failed", fd);
        }
        return true;
    }

    inline bool uncork() {
        if (!tcp_nopush) {
            return false;
        }
        if (set_tcp_nopush(0) < 0) {
            swSysWarn("set_tcp_nopush(fd=%d, OFF) failed", fd);
            return false;
        }
        // Restore tcp_nodelay setting
        if (enable_tcp_nodelay && tcp_nodelay == 0 && set_tcp_nodelay(1) != 0) {
            swSysWarn("set_tcp_nodelay(fd=%d, ON) failed", fd);
            return false;
        }
        return true;
    }

    int wait_event(int timeout_ms, int events);
    void free();

    static inline int is_dgram(swSocket_type type) {
        return (type == SW_SOCK_UDP || type == SW_SOCK_UDP6 || type == SW_SOCK_UNIX_DGRAM);
    }

    static inline int is_stream(swSocket_type type) {
        return (type == SW_SOCK_TCP || type == SW_SOCK_TCP6 || type == SW_SOCK_UNIX_STREAM);
    }

    bool is_stream() {
        return socket_type == SW_SOCK_TCP || socket_type == SW_SOCK_TCP6 || socket_type == SW_SOCK_UNIX_STREAM;
    }

    bool is_dgram() {
        return socket_type == SW_SOCK_UDP || socket_type == SW_SOCK_UDP6 || socket_type == SW_SOCK_UNIX_DGRAM;
    }

    bool is_inet4() {
        return socket_type == SW_SOCK_TCP || socket_type == SW_SOCK_UDP;
    }

    bool is_inet6() {
        return socket_type == SW_SOCK_TCP6 || socket_type == SW_SOCK_UDP6;
    }

    bool is_inet() {
        return is_inet4() || is_inet6();
    }

    bool is_local() {
        return socket_type == SW_SOCK_UNIX_STREAM || socket_type == SW_SOCK_UNIX_DGRAM;
    }

    ssize_t sendto_blocking(const Address &dst_addr, const void *__buf, size_t __n, int flags = 0);
    ssize_t recvfrom_blocking(char *__buf, size_t __len, int flags, Address *sa);

    inline ssize_t sendto(const char *dst_host, int dst_port, const void *data, size_t len, int flags = 0) {
        Address addr = {};
        if (!addr.assign(socket_type, dst_host, dst_port)) {
            return SW_ERR;
        }
        return sendto(addr, data, len, flags);
    }

    inline ssize_t sendto(const Address &dst_addr, const void *data, size_t len, int flags) {
        return ::sendto(fd, data, len, flags, &dst_addr.addr.ss, dst_addr.len);
    }

    inline int catch_error(int err) {
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

    static inline enum swSocket_type convert_to_type(int domain, int type, int protocol = 0) {
        switch (domain) {
        case AF_INET:
            return type == SOCK_STREAM ? SW_SOCK_TCP : SW_SOCK_UDP;
        case AF_INET6:
            return type == SOCK_STREAM ? SW_SOCK_TCP6 : SW_SOCK_UDP6;
        case AF_UNIX:
            return type == SOCK_STREAM ? SW_SOCK_UNIX_STREAM : SW_SOCK_UNIX_DGRAM;
        default:
            return SW_SOCK_TCP;
        }
    }

    static inline enum swSocket_type convert_to_type(std::string &host) {
        if (host.compare(0, 6, "unix:/", 0, 6) == 0) {
            host = host.substr(sizeof("unix:") - 1);
            host.erase(0, host.find_first_not_of('/') - 1);
            return SW_SOCK_UNIX_STREAM;
        } else if (host.find(':') != std::string::npos) {
            return SW_SOCK_TCP6;
        } else {
            return SW_SOCK_TCP;
        }
    }

    static inline int get_domain_and_type(enum swSocket_type type, int *sock_domain, int *sock_type) {
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
};

int gethostbyname(int type, const char *name, char *addr);
int getaddrinfo(GetaddrinfoRequest *req);

}  // namespace network
network::Socket *make_socket(int fd, enum swFd_type fd_type);
network::Socket *make_socket(enum swSocket_type socket_type, enum swFd_type fd_type, int flags);
network::Socket *make_server_socket(enum swSocket_type socket_type,
                                    const char *address,
                                    int port = 0,
                                    int backlog = SW_BACKLOG);
bool verify_ip(int __af, const std::string &str);
}  // namespace swoole
