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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <netinet/in.h>
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <sys/types.h>
#endif
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <string>
#include <vector>

#include "swoole.h"
#include "swoole_ssl.h"
#include "swoole_buffer.h"
#include "swoole_file.h"

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#ifdef __sun
#define s6_addr8 _S6_un._S6_u8
#define s6_addr16 _S6_un._S6_u16
#define s6_addr32 _S6_un._S6_u32
#endif

// OS Feature
#if defined(HAVE_KQUEUE) || !defined(HAVE_SENDFILE)
ssize_t swoole_sendfile(int out_fd, int in_fd, off_t *offset, size_t size);
#else
#include <sys/sendfile.h>
#define swoole_sendfile(out_fd, in_fd, offset, limit) sendfile(out_fd, in_fd, offset, limit)
#endif

enum {
    SW_BAD_SOCKET = -1,
};

namespace swoole {
struct GethostbynameRequest;
struct GetaddrinfoRequest;

namespace network {

struct SendfileTask {
    off_t offset;
    size_t length;
    char filename[0];
};

struct SendfileRequest {
    File file;
    int8_t corked;
    off_t begin;
    off_t end;

  public:
    SendfileRequest(const char *filename, off_t _offset) : file(filename, O_RDONLY) {
        begin = _offset;
        end = 0;
        corked = 0;
    }

    const char *get_filename() const {
        return file.get_path().c_str();
    }
};

struct Address {
    union {
        sockaddr ss;
        sockaddr_in inet_v4;
        sockaddr_in6 inet_v6;
        sockaddr_un un;
    } addr;
    socklen_t len;
    SocketType type;

    bool assign(SocketType _type, const std::string &_host, int _port = 0, bool _resolve_name = true);
    bool assign(const std::string &url);

    int get_port() const;
    void set_port(int _port);
    const char *get_addr() const;
    bool is_loopback_addr();
    bool empty() const;
    static const char *type_str(SocketType type);

    static bool verify_ip(int __af, const std::string &str) {
        char tmp_address[INET6_ADDRSTRLEN];
        return inet_pton(__af, str.c_str(), tmp_address) == 1;
    }
};

struct IOVector {
    // we should modify iov_iterator instead of iov, iov is readonly
    iovec *iov = nullptr;
    iovec *iov_iterator = nullptr;
    int count = 0;
    int remain_count = 0;
    int index = 0;
    size_t offset_bytes = 0;

    IOVector(iovec *_iov, int _iovcnt);
    ~IOVector();

    void update_iterator(ssize_t __n);

    iovec *get_iterator() const {
        return iov_iterator;
    }

    size_t length() {
        size_t len = 0;
        SW_LOOP_N(count) {
            len += iov[i].iov_len;
        }
        return len;
    }

    int get_remain_count() const {
        return remain_count;
    }

    int get_index() const {
        return index;
    }

    size_t get_offset_bytes() const {
        return offset_bytes;
    }
};

struct Socket {
    static double default_dns_timeout;
    static double default_connect_timeout;
    static double default_read_timeout;
    static double default_write_timeout;
    static uint32_t default_buffer_size;

    int fd;
    FdType fd_type;
    SocketType socket_type;
    int events;
    bool enable_tcp_nodelay;

    uchar removed : 1;
    uchar silent_remove : 1;
    uchar nonblock : 1;
    uchar cloexec : 1;
    uchar direct_send : 1;
    uchar bound : 1;
    uchar listened : 1;
#ifdef SW_USE_OPENSSL
    uchar ssl_send_ : 1;
    uchar ssl_want_read : 1;
    uchar ssl_want_write : 1;
    uchar ssl_renegotiation : 1;
    uchar ssl_handshake_buffer_set : 1;
    uchar ssl_quiet_shutdown : 1;
    uchar ssl_closed_ : 1;
#ifdef SW_SUPPORT_DTLS
    uchar dtls : 1;
#endif
#endif
    uchar close_wait : 1;
    uchar send_wait : 1;
    uchar tcp_nopush : 1;
    uchar tcp_nodelay : 1;
    uchar skip_recv : 1;
    uchar recv_wait : 1;
    uchar event_hup : 1;
    uchar dont_restart : 1;

    // memory buffer size [user space]
    uint32_t buffer_size;
    uint32_t chunk_size;

    void *object;

#ifdef SW_USE_OPENSSL
    SSL *ssl;
    uint32_t ssl_state;
#endif

    /**
     * Only used for getsockname, written by the OS, not user. This is the exact actual address.
     */
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

    // for reactor
    int handle_send();
    int handle_sendfile();
    // user space memory buffer
    void set_memory_buffer_size(uint32_t _buffer_size) {
        buffer_size = _buffer_size;
    }
    // socket option [kernel buffer]
    bool set_buffer_size(uint32_t _buffer_size);
    bool set_recv_buffer_size(uint32_t _buffer_size);
    bool set_send_buffer_size(uint32_t _buffer_size);
    bool set_timeout(double timeout);
    bool set_recv_timeout(double timeout);
    bool set_send_timeout(double timeout);

    bool set_nonblock() {
        return set_fd_option(1, -1);
    }

    bool set_block() {
        return set_fd_option(0, -1);
    }

    bool set_fd_option(int _nonblock, int _cloexec);

    int set_option(int level, int optname, int optval) const {
        return setsockopt(fd, level, optname, &optval, sizeof(optval));
    }

    int set_option(int level, int optname, const void *optval, socklen_t optlen) const {
        return setsockopt(fd, level, optname, optval, optlen);
    }

    int get_option(int level, int optname, void *optval, socklen_t *optlen) const {
        return getsockopt(fd, level, optname, optval, optlen);
    }

    int get_option(int level, int optname, int *optval) const {
        socklen_t optlen = sizeof(*optval);
        return get_option(level, optname, optval, &optlen);
    }

    int get_fd() const {
        return fd;
    }

    const char *get_addr() const {
        return info.get_addr();
    }

    int get_port() const {
        return info.get_port();
    }

    uint32_t get_out_buffer_length() const {
        return out_buffer ? out_buffer->length() : 0;
    }

    int move_fd() {
        int sock_fd = fd;
        fd = SW_BAD_SOCKET;
        return sock_fd;
    }

    int get_name();
    int get_peer_name(Address *sa);
    int set_tcp_nopush(int nopush);

    int set_reuse_addr(int enable = 1) const {
        return set_option(SOL_SOCKET, SO_REUSEADDR, enable);
    }

    int set_reuse_port(int enable = 1) const {
#ifdef SO_REUSEPORT
        return set_option(SOL_SOCKET, SO_REUSEPORT, enable);
#endif
        return -1;
    }

    bool set_tcp_nodelay(int nodelay = 1);
    bool check_liveness();

    int sendfile_async(const char *filename, off_t offset, size_t length);
    int sendfile_sync(const char *filename, off_t offset, size_t length, double timeout);
    ssize_t sendfile(const File &fp, off_t *offset, size_t length);

    ssize_t recv(void *__buf, size_t __n, int __flags);
    ssize_t send(const void *__buf, size_t __n, int __flags);
    ssize_t peek(void *__buf, size_t __n, int __flags);
    Socket *accept();
    Socket *dup() const;

    ssize_t readv(IOVector *io_vector);
    ssize_t writev(IOVector *io_vector);

    ssize_t writev(const struct iovec *iov, size_t iovcnt) {
        return ::writev(fd, iov, iovcnt);
    }

    /**
     * If the port is 0, the system will automatically allocate an available port.
     */
    int bind(const std::string &_host, int port = 0);

    int bind(const Address &addr) {
        return bind(&addr.addr.ss, addr.len);
    }

    int bind(const struct sockaddr *sa, socklen_t len);
    int listen(int backlog = 0);

    void clean();
    ssize_t send_sync(const void *__data, size_t __len, int flags = 0);
    ssize_t send_async(const void *__data, size_t __len);
    ssize_t recv_sync(void *__data, size_t __len, int flags = 0);
    ssize_t writev_sync(const struct iovec *iov, size_t iovcnt);

    int connect(const Address &sa) {
        return ::connect(fd, &sa.addr.ss, sa.len);
    }

    int connect(const Address *sa) {
        return ::connect(fd, &sa->addr.ss, sa->len);
    }

    int connect(const std::string &host, int port) {
        Address addr;
        addr.assign(socket_type, host, port);
        return connect(addr);
    }

    int connect_sync(const Address &sa, double timeout);

#ifdef SW_USE_OPENSSL
    void ssl_clear_error() {
        ERR_clear_error();
        ssl_want_read = 0;
        ssl_want_write = 0;
    }
    int ssl_create(SSLContext *_ssl_context, int _flags);
    int ssl_connect();
    ReturnCode ssl_accept();
    ssize_t ssl_recv(void *__buf, size_t __n);
    ssize_t ssl_send(const void *__buf, size_t __n);
    ssize_t ssl_readv(IOVector *io_vector);
    ssize_t ssl_writev(IOVector *io_vector);
    ssize_t ssl_sendfile(const File &fp, off_t *offset, size_t size);
    STACK_OF(X509) * ssl_get_peer_cert_chain();
    std::vector<std::string> ssl_get_peer_cert_chain(int limit);
    X509 *ssl_get_peer_certificate();
    int ssl_get_peer_certificate(char *buf, size_t n);
    bool ssl_get_peer_certificate(String *buf);
    bool ssl_verify(bool allow_self_signed);
    bool ssl_check_host(const char *tls_host_name);
    void ssl_catch_error();
    bool ssl_shutdown();
    void ssl_close();
    static const char *ssl_get_error_reason(int *reason);
#endif

    ssize_t recvfrom(char *__buf, size_t __len, int flags, Address *sa) {
        sa->len = sizeof(sa->addr);
        return recvfrom(__buf, __len, flags, &sa->addr.ss, &sa->len);
    }

    ssize_t recvfrom(char *buf, size_t len, int flags, sockaddr *addr, socklen_t *addr_len);
    ssize_t recvfrom_sync(char *__buf, size_t __len, int flags, Address *sa);
    ssize_t recvfrom_sync(char *__buf, size_t __len, int flags, sockaddr *addr, socklen_t *addr_len);

    bool cork();
    bool uncork();

    bool isset_readable_event() {
        return events & SW_EVENT_READ;
    }

    bool isset_writable_event() {
        return events & SW_EVENT_WRITE;
    }

    int wait_event(int timeout_ms, int events);
    bool wait_for(const std::function<swReturnCode(void)> &fn, int event, double timeout = -1);
    int what_event_want(int default_event);
    void free();

    static inline bool is_dgram(SocketType type) {
        return type == SW_SOCK_UDP || type == SW_SOCK_UDP6 || type == SW_SOCK_UNIX_DGRAM;
    }

    static inline bool is_stream(SocketType type) {
        return type == SW_SOCK_TCP || type == SW_SOCK_TCP6 || type == SW_SOCK_UNIX_STREAM;
    }

    static inline bool is_inet4(SocketType type) {
        return type == SW_SOCK_TCP || type == SW_SOCK_UDP || type == SW_SOCK_RAW;
    }

    static inline bool is_inet6(SocketType type) {
        return type == SW_SOCK_TCP6 || type == SW_SOCK_UDP6 || type == SW_SOCK_RAW6;
    }

    static inline bool is_tcp(SocketType type) {
        return type == SW_SOCK_TCP || type == SW_SOCK_TCP6;
    }

    static inline bool is_udp(SocketType type) {
        return type == SW_SOCK_UDP || type == SW_SOCK_UDP6;
    }

    static inline bool is_local(SocketType type) {
        return type == SW_SOCK_UNIX_STREAM || type == SW_SOCK_UNIX_DGRAM;
    }

    static inline bool is_raw(SocketType type) {
        return type == SW_SOCK_RAW || type == SW_SOCK_RAW6;
    }

    bool is_stream() {
        return is_stream(socket_type);
    }

    bool is_tcp() {
        return is_tcp(socket_type);
    }

    bool is_udp() {
        return is_udp(socket_type);
    }

    bool is_dgram() {
        return is_dgram(socket_type);
    }

    bool is_inet4() {
        return is_inet4(socket_type);
    }

    bool is_inet6() {
        return is_inet6(socket_type);
    }

    bool is_inet() {
        return is_inet4() || is_inet6();
    }

    bool is_local() {
        return is_local(socket_type);
    }

    bool is_raw() {
        return is_raw(socket_type);
    }

    ssize_t write(const void *__buf, size_t __len) {
        return ::write(fd, __buf, __len);
    }

    ssize_t read(void *__buf, size_t __len) {
        return ::read(fd, __buf, __len);
    }

    /**
     * Read data from the socket synchronously without setting non-blocking or blocking IO,
     * and allow interruptions by signals.
     */
    ssize_t read_sync(void *__buf, size_t __len, int timeout_ms = -1);

    /**
     * Write data to the socket synchronously without setting non-blocking or blocking IO,
     * and allow interruptions by signals.
     */
    ssize_t write_sync(const void *__buf, size_t __len, int timeout_ms = -1);

    int shutdown(int __how) {
        return ::shutdown(fd, __how);
    }

    ssize_t sendto_sync(const Address &dst_addr, const void *__buf, size_t __n, int flags = 0);

    ssize_t sendto(const char *dst_host, int dst_port, const void *data, size_t len, int flags = 0) const {
        Address addr = {};
        if (!addr.assign(socket_type, dst_host, dst_port)) {
            return SW_ERR;
        }
        return sendto(addr, data, len, flags);
    }

    ssize_t sendto(const Address &dst_addr, const void *data, size_t len, int flags = 0) const {
        return ::sendto(fd, data, len, flags, &dst_addr.addr.ss, dst_addr.len);
    }

    int catch_error(int err);

    int catch_write_error(const int err) {
        switch (err) {
        case ENOBUFS:
            return SW_WAIT;
        default:
            return catch_error(err);
        }
    }

    int catch_write_pipe_error(const int err) {
        switch (err) {
        case ENOBUFS:
        case EMSGSIZE:
            return SW_REDUCE_SIZE;
        default:
            return catch_error(err);
        }
    }

    int catch_read_error(const int err) {
        return catch_error(err);
    }

    static SocketType convert_to_type(int domain, int type);
    static SocketType convert_to_type(std::string &host);
    static int get_domain_and_type(SocketType type, int *sock_domain, int *sock_type);
};

int gethostbyname(int type, const char *name, char *addr);
int gethostbyname(const GethostbynameRequest *req);
int getaddrinfo(GetaddrinfoRequest *req);

}  // namespace network

/**
 * This function will never return NULL; if memory allocation fails, a C++ exception will be thrown.
 * Must use the `socket->free()` function to release the object pointer instead of the `delete` operator.
 * When the socket is released, it will close the file descriptor (fd).
 * If you do not want the fd to be closed, use `socket->move_fd()` to relinquish ownership of the fd.
 */
network::Socket *make_socket(int fd, FdType fd_type);
/**
 * The following three functions will return a null pointer if the socket creation fails.
 * It is essential to check the return value;
 * if it is nullptr, you should inspect errno to determine the cause of the error.
 */
network::Socket *make_socket(SocketType socket_type, FdType fd_type, int flags);
network::Socket *make_socket(
    SocketType type, FdType fd_type, int sock_domain, int sock_type, int socket_protocol, int flags);
int socket(int sock_domain, int sock_type, int socket_protocol, int flags);
network::Socket *make_server_socket(SocketType socket_type,
                                    const char *address,
                                    int port = 0,
                                    int backlog = SW_BACKLOG);
/**
 * Verify if the input string is an IP address,
 * where AF_INET indicates an IPv4 address, such as 192.168.1.100,
 * and AF_INET6 indicates an IPv6 address, for example, 2001:0000:130F:0000:0000:09C0:876A:130B.
 */
bool verify_ip(int __af, const std::string &str);
}  // namespace swoole
