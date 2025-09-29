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

#ifdef __linux__
#include <sys/sendfile.h>
#define swoole_sendfile(out_fd, in_fd, offset, limit) sendfile(out_fd, in_fd, offset, limit)
#else
ssize_t swoole_sendfile(int out_fd, int in_fd, off_t *offset, size_t size);
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

    /**
     * Assign an address based on the socket type and host/port.
     * For IPv4, the host can be an IP address like "192.168.1.100"
     * or a domain name like "www.example.com".
     * For IPv6, the host can be an IP address like "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
     * or a domain name like "ipv6.example.com".
     * For UNIX socket, the host is the path to the socket file.
     * If _port is 0, it will not set the port.
     * If _resolve_name is false, it will not resolve the domain name.
     *
     * Returns true on success, false on failure.
     */
    bool assign(SocketType _type, const std::string &_host, int _port = 0, bool _resolve_name = true);
    /**
     * Assign an address based on a URL string.
     * The format of the URL can be:
     * - tcp://hostname:port
     * - udp://hostname:port
     * - tcp://[IPv6_address]:port
     * - udp://[IPv6_address]:port
     * - unix:///path/to/socket
     * - udg:///path/to/socket
     *
     * Returns true on success, false on failure.
     */
    bool assign(const std::string &url);

    int get_port() const;
    void set_port(int _port);
    const char *get_addr() const;
    bool is_loopback_addr() const;
    bool empty() const;

    /**
     * Get the string representation of the address
     */
    static const char *type_str(SocketType type);
    /**
     * Convert the address to a string representation.
     * For IPv4, it will be in the format "192.168.1.100"
     * For IPv6, it will be in the format "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
     * For UNIX socket, it will be the path of the socket file.
     * The returned pointer is a static buffer, so it should not be freed.
     */
    static const char *addr_str(int family, const void *addr);
    /**
     * Verify if the input string is an IP address,
     * where AF_INET indicates an IPv4 address, such as 192.168.1.100,
     * and AF_INET6 indicates an IPv6 address, for example, 2001:0000:130F:0000:0000:09C0:876A:130B.
     */
    static bool verify_ip(int family, const std::string &str);
    static bool verify_port(int port, bool for_connect = false);
};

struct IOVector {
    // we should modify iov_iterator instead of iov, iov is readonly
    iovec *iov = nullptr;
    iovec *iov_iterator = nullptr;
    int count = 0;
    int remain_count = 0;
    int index = 0;
    size_t offset_bytes = 0;

    IOVector(const iovec *_iov, int _iovcnt);
    ~IOVector();

    void update_iterator(ssize_t _n);

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
    bool kernel_nobufs;

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
    /**
     * The default setting is false, meaning that system calls interrupted by signals will be automatically retried. If
     * set to true, the call will not be retried but will immediately return -1, setting errno to EINTR. In this case,
     * the caller must explicitly handle this error.
     */
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
    double dns_timeout = default_dns_timeout;
    double connect_timeout = default_connect_timeout;
    double read_timeout = default_read_timeout;
    double write_timeout = default_write_timeout;

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
    // socket option [kernel space]
    bool set_buffer_size(uint32_t _buffer_size) const;
    bool set_recv_buffer_size(uint32_t _buffer_size) const;
    bool set_send_buffer_size(uint32_t _buffer_size) const;
    bool set_kernel_read_timeout(double timeout);
    bool set_kernel_write_timeout(double timeout);

    bool set_kernel_timeout(double timeout) {
        return set_kernel_read_timeout(timeout) && set_kernel_write_timeout(timeout);
    }

    // socket option [user space]
    void set_timeout(double timeout, int type = SW_TIMEOUT_ALL);
    double get_timeout(TimeoutType type) const;
    bool has_timedout() const;
    bool has_kernel_nobufs();

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
    int get_peer_name(Address *sa) const;
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
    int sendfile_sync(const char *filename, off_t offset, size_t length);
    ssize_t sendfile(const File &fp, off_t *offset, size_t length);

    ssize_t recv(void *_buf, size_t _n, int _flags);
    ssize_t send(const void *_buf, size_t _n, int _flags);
    ssize_t peek(void *_buf, size_t _n, int _flags) const;
    Socket *accept();
    Socket *dup() const;

    ssize_t readv(IOVector *io_vector);
    ssize_t writev(IOVector *io_vector);

    ssize_t writev(const iovec *iov, size_t iovcnt) const {
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

    void clean() const;
    ssize_t send_sync(const void *_data, size_t _len, int flags = 0);
    ssize_t send_async(const void *_data, size_t _len);
    ssize_t recv_sync(void *_data, size_t _len, int flags = 0);
    ssize_t writev_sync(const iovec *iov, size_t iovcnt);

    int connect(const Address &sa) const {
        return ::connect(fd, &sa.addr.ss, sa.len);
    }

    int connect(const Address *sa) const {
        return ::connect(fd, &sa->addr.ss, sa->len);
    }

    int connect(const std::string &host, int port) const {
        Address addr;
        addr.assign(socket_type, host, port);
        return connect(addr);
    }

    int connect_sync(const Address &sa);
    ReturnCode connect_async(const Address &sa);

#ifdef SW_USE_OPENSSL
    void ssl_clear_error() {
        ERR_clear_error();
        ssl_want_read = 0;
        ssl_want_write = 0;
    }
    /**
     * This function does not set the last error; to obtain internal SSL error information, you should call
     * ERR_get_error().
     */
    int ssl_create(SSLContext *_ssl_context, int _flags);
    int ssl_connect();
    ReturnCode ssl_accept();
    ssize_t ssl_recv(void *_buf, size_t _n);
    ssize_t ssl_send(const void *_buf, size_t _n);
    ssize_t ssl_readv(IOVector *io_vector);
    ssize_t ssl_writev(IOVector *io_vector);
    ssize_t ssl_sendfile(const File &fp, off_t *offset, size_t size);
    STACK_OF(X509) * ssl_get_peer_cert_chain() const;
    std::vector<std::string> ssl_get_peer_cert_chain(int limit) const;
    X509 *ssl_get_peer_certificate() const;
    int ssl_get_peer_certificate(char *buf, size_t n) const;
    bool ssl_get_peer_certificate(String *buf) const;
    bool ssl_verify(bool allow_self_signed) const;
    bool ssl_check_host(const char *tls_host_name) const;
    void ssl_catch_error() const;
    bool ssl_shutdown();
    void ssl_close();
    static const char *ssl_get_error_reason(int *reason);
#endif

    ssize_t recvfrom(char *_buf, size_t _len, int flags, Address *sa) const {
        sa->len = sizeof(sa->addr);
        return recvfrom(_buf, _len, flags, &sa->addr.ss, &sa->len);
    }

    ssize_t recvfrom(char *buf, size_t len, int flags, sockaddr *addr, socklen_t *addr_len) const;
    ssize_t recvfrom_sync(char *_buf, size_t _len, int flags, Address *sa);
    ssize_t recvfrom_sync(char *_buf, size_t _len, int flags, sockaddr *addr, socklen_t *addr_len);

    bool cork();
    bool uncork();

    bool isset_readable_event() const {
        return events & SW_EVENT_READ;
    }

    bool isset_writable_event() const {
        return events & SW_EVENT_WRITE;
    }

    int wait_event(int timeout_ms, int events) const;
    bool wait_for(const std::function<ReturnCode()> &fn, int event, int timeout_msec = -1);
    int what_event_want(int default_event) const;
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

    bool is_stream() const {
        return is_stream(socket_type);
    }

    bool is_tcp() const {
        return is_tcp(socket_type);
    }

    bool is_udp() const {
        return is_udp(socket_type);
    }

    bool is_dgram() const {
        return is_dgram(socket_type);
    }

    bool is_inet4() const {
        return is_inet4(socket_type);
    }

    bool is_inet6() const {
        return is_inet6(socket_type);
    }

    bool is_inet() const {
        return is_inet4() || is_inet6();
    }

    bool is_local() const {
        return is_local(socket_type);
    }

    bool is_raw() const {
        return is_raw(socket_type);
    }

    ssize_t write(const void *_buf, size_t _len) const {
        return ::write(fd, _buf, _len);
    }

    ssize_t read(void *_buf, size_t _len) const {
        return ::read(fd, _buf, _len);
    }

    /**
     * Read data from the socket synchronously without setting non-blocking or blocking IO,
     * and allow interruptions by signals.
     */
    ssize_t read_sync(void *_buf, size_t _len);

    /**
     * Write data to the socket synchronously without setting non-blocking or blocking IO,
     * and allow interruptions by signals.
     */
    ssize_t write_sync(const void *_buf, size_t _len);

    int shutdown(int _how) const {
        return ::shutdown(fd, _how);
    }

    ssize_t sendto_sync(const Address &dst_addr, const void *_buf, size_t _n, int flags = 0);

    ssize_t sendto(const char *dst_host, int dst_port, const void *data, size_t len, int flags = 0) const {
        Address addr;
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
        return catch_error(err);
    }

    int catch_write_pipe_error(const int err) {
        switch (err) {
        case ENOBUFS:
#ifdef __linux__
            kernel_nobufs = true;
            return SW_REDUCE_SIZE;
#else
            return catch_error(err);
#endif
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

std::string gethostbyname(int type, const std::string &name);
int gethostbyname(int type, const char *name, char *addr);
int gethostbyname(GethostbynameRequest *req);
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
}  // namespace swoole
