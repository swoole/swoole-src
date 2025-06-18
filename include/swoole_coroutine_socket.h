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

#include "swoole.h"
#include "swoole_socket.h"
#include "swoole_coroutine.h"
#include "swoole_protocol.h"
#include "swoole_proxy.h"

#include <vector>

namespace swoole {
namespace coroutine {
//-------------------------------------------------------------------------------
/**
 * @return true: continue to wait for events
 * @return false: stop event waiting and resume coroutine
 */
using EventBarrier = std::function<bool()>;

class Socket {
  public:
    int errCode = 0;
    const char *errMsg = "";
    std::string errString;

    bool open_length_check = false;
    bool open_eof_check = false;
    bool http2 = false;

    Protocol protocol = {};
    std::unique_ptr<Socks5Proxy> socks5_proxy = nullptr;
    std::unique_ptr<HttpProxy> http_proxy = nullptr;

    static TimeoutType timeout_type_list[4];

    Socket(int domain, int type, int protocol);
    Socket(int _fd, int _domain, int _type, int _protocol);
    explicit Socket(SocketType type = SW_SOCK_TCP);
    Socket(int _fd, SocketType _type);
    ~Socket();
    /**
     * If SSL is enabled, an SSL handshake will automatically take place during the connect() method.
     * When connect() returns true, it indicates that the TCP connection has been successfully
     * established and the SSL handshake has also succeeded.
     */
    bool connect(const std::string &host, int port = 0, int flags = 0);
    bool connect(const sockaddr *addr, socklen_t addrlen);
    bool shutdown(int how = SHUT_RDWR);
    bool cancel(EventType event);
    bool close();

    bool is_connected() const {
        return connected && !is_closed();
    }

    bool is_closed() const {
        return sock_fd == SW_BAD_SOCKET;
    }

    bool is_port_required() const {
        return type <= SW_SOCK_UDP6;
    }

    bool check_liveness();
    ssize_t peek(void *_buf, size_t _n);
    ssize_t recv(void *_buf, size_t _n);
    ssize_t send(const void *_buf, size_t _n);

    ssize_t send(const std::string &buf) {
        return send(buf.c_str(), buf.length());
    }

    /**
     * The read()/write()/recvmsg()/sendmsg() functions currently does not support SSL
     */
    ssize_t read(void *_buf, size_t _n);
    ssize_t write(const void *__buf, size_t __n);
    ssize_t recvmsg(msghdr *msg, int flags);
    ssize_t sendmsg(const msghdr *msg, int flags);

    ssize_t readv(network::IOVector *io_vector);
    ssize_t readv_all(network::IOVector *io_vector);
    ssize_t writev(network::IOVector *io_vector);
    ssize_t writev_all(network::IOVector *io_vector);
    ssize_t recv_all(void *__buf, size_t __n);
    ssize_t send_all(const void *__buf, size_t __n);
    ssize_t recv_packet(double timeout = 0);
    ssize_t recv_line(void *__buf, size_t maxlen);
    ssize_t recv_with_buffer(void *__buf, size_t __n);

    char *pop_packet() const {
        if (read_buffer->offset == 0) {
            return nullptr;
        } else {
            return read_buffer->pop(buffer_init_size);
        }
    }

    bool poll(EventType type, double timeout = 0);
    /**
     * If the server has SSL enabled, you must explicitly call `ssl_handshake()`,
     * as it will not be automatically executed within the `accept()` function.
     * This behavior is inconsistent with `connect()`, which internally executes `ssl_handshake()` automatically,
     * thus not requiring an explicit call at the application level.
     * The reason for this design is that `ssl_handshake()` can typically be performed concurrently within a separate
     * client coroutine. If `ssl_handshake()` were to be automatically executed inside the `accept()` function,
     * it would block the server's listening coroutine,
     * causing the `ssl_handshake()` processes to execute sequentially rather than in parallel.
     */
    Socket *accept(double timeout = 0);
    bool bind(const std::string &address, int port = 0);
    bool bind(const sockaddr *sa, socklen_t len) const;
    bool listen(int backlog = 0);
    bool sendfile(const char *filename, off_t offset, size_t length);
    ssize_t sendto(std::string host, int port, const void *__buf, size_t __n);
    ssize_t recvfrom(void *__buf, size_t __n);
    ssize_t recvfrom(void *__buf, size_t __n, sockaddr *_addr, socklen_t *_socklen);

#ifdef SW_USE_OPENSSL
    /**
     * Operation sequence:
     * 1. enable_ssl_encrypt()
     * 2. Set SSL parameters, such as certificate file, key file
     * 3. ssl_handshake(), to be executed after connect or accept
     */
    bool enable_ssl_encrypt() {
        if (ssl_context.get()) {
            return false;
        }
        ssl_context = std::make_shared<SSLContext>();
        return true;
    }

    bool ssl_is_enable() const {
        return get_ssl_context() != nullptr;
    }

    SSLContext *get_ssl_context() const {
        return ssl_context.get();
    }

    bool ssl_handshake();
    bool ssl_verify(bool allow_self_signed);
    std::string ssl_get_peer_cert();

    bool set_ssl_key_file(const std::string &file) const {
        return ssl_context->set_key_file(file);
    }

    bool set_ssl_cert_file(const std::string &file) const {
        return ssl_context->set_cert_file(file);
    }

    void set_ssl_cafile(const std::string &file) const {
        ssl_context->cafile = file;
    }

    void set_ssl_capath(const std::string &path) const {
        ssl_context->capath = path;
    }

    void set_ssl_passphrase(const std::string &str) const {
        ssl_context->passphrase = str;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    void set_tls_host_name(const std::string &str) const {
        ssl_context->tls_host_name = str;
        // if user set empty ssl_host_name, disable it, otherwise the underlying may set it automatically
        ssl_context->disable_tls_host_name = ssl_context->tls_host_name.empty();
    }
#endif

    void set_ssl_dhparam(const std::string &file) const {
        ssl_context->dhparam = file;
    }

    void set_ssl_ecdh_curve(const std::string &str) const {
        ssl_context->ecdh_curve = str;
    }

    void set_ssl_protocols(long protocols) const {
        ssl_context->protocols = protocols;
    }

    void set_ssl_disable_compress(bool value) const {
        ssl_context->disable_compress = value;
    }

    void set_ssl_verify_peer(bool value) const {
        ssl_context->verify_peer = value;
    }

    void set_ssl_allow_self_signed(bool value) const {
        ssl_context->allow_self_signed = value;
    }

    void set_ssl_verify_depth(uint8_t value) const {
        ssl_context->verify_depth = value;
    }

    void set_ssl_ciphers(const std::string &str) const {
        ssl_context->ciphers = str;
    }

#ifdef OPENSSL_IS_BORINGSSL
    void set_ssl_grease(uint8_t value) {
        ssl_context->grease = value;
    }
#endif

    const std::string &get_ssl_cert_file() const {
        return ssl_context->cert_file;
    }

    const std::string &get_ssl_key_file() const {
        return ssl_context->key_file;
    }
#endif

    static inline void init_reactor(Reactor *reactor) {
        reactor->set_handler(SW_FD_CO_SOCKET, SW_EVENT_READ, readable_event_callback);
        reactor->set_handler(SW_FD_CO_SOCKET, SW_EVENT_WRITE, writable_event_callback);
        reactor->set_handler(SW_FD_CO_SOCKET, SW_EVENT_ERROR, error_event_callback);
    }

    SocketType get_type() const {
        return type;
    }

    FdType get_fd_type() const {
        return socket->fd_type;
    }

    int get_sock_domain() const {
        return sock_domain;
    }

    int get_sock_type() const {
        return sock_type;
    }

    int get_sock_protocol() const {
        return sock_protocol;
    }

    int get_fd() const {
        return sock_fd;
    }

    network::Socket *get_socket() const {
        return socket;
    }

    bool getsockname() const;
    bool getpeername(network::Address *sa);

    const char *get_addr() const {
        return socket->get_addr();
    }

    int get_port() const {
        return socket->get_port();
    }

    bool has_bound(const EventType event = SW_EVENT_RDWR) const {
        return get_bound_co(event) != nullptr;
    }

    Coroutine *get_bound_co(const EventType event) const {
        if (event & SW_EVENT_READ) {
            if (read_co) {
                return read_co;
            }
        }
        if (event & SW_EVENT_WRITE) {
            if (write_co) {
                return write_co;
            }
        }
        return nullptr;
    }

    long get_bound_cid(const EventType event = SW_EVENT_RDWR) const {
        Coroutine *co = get_bound_co(event);
        return co ? co->get_cid() : 0;
    }

    const char *get_event_str(EventType event) const;

    void check_bound_co(const EventType event) const {
        long cid = get_bound_cid(event);
        if (sw_unlikely(cid)) {
            swoole_fatal_error(SW_ERROR_CO_HAS_BEEN_BOUND,
                               "Socket#%d has already been bound to another coroutine#%ld, "
                               "%s of the same socket in coroutine#%ld at the same time is not allowed",
                               sock_fd,
                               cid,
                               get_event_str(event),
                               Coroutine::get_current_cid());
        }
    }

    void set_err(const int e) {
        errCode = errno = e;
        swoole_set_last_error(errCode);
        errMsg = e ? swoole_strerror(e) : "";
    }

    void set_err() {
        errCode = swoole_get_last_error();
        errMsg = swoole_strerror(errCode);
    }

    void set_err(const int e, const char *s) {
        errCode = errno = e;
        swoole_set_last_error(errCode);
        errMsg = s;
    }

    void set_err(const int e, const std::string &s) {
        errCode = errno = e;
        swoole_set_last_error(errCode);
        errString = s;
        errMsg = errString.c_str();
    }

    /* set connect read write timeout */
    void set_timeout(double timeout, int type = SW_TIMEOUT_ALL);

    void set_timeout(timeval *timeout, int type = SW_TIMEOUT_ALL) {
        set_timeout((double) timeout->tv_sec + ((double) timeout->tv_usec / 1000 / 1000), type);
    }

    double get_timeout(TimeoutType type) const;
    bool get_option(int level, int optname, void *optval, socklen_t *optlen) const;
    bool get_option(int level, int optname, int *optval) const;
    bool set_option(int level, int optname, const void *optval, socklen_t optlen) const;
    bool set_option(int level, int optname, int optval) const;
    void set_socks5_proxy(const std::string &host, int port, const std::string &user = "", const std::string &pwd = "");
    void set_http_proxy(const std::string &host, int port, const std::string &user = "", const std::string &pwd = "");
    String *get_read_buffer();
    String *get_write_buffer();
    String *pop_read_buffer();
    String *pop_write_buffer();

    void set_resolve_context(NameResolver::Context *ctx) {
        resolve_context_ = ctx;
    }

    void set_dtor(const std::function<void(Socket *)> &dtor) {
        dtor_ = dtor;
    }

    void set_zero_copy(bool enable) {
        zero_copy = enable;
    }

    void set_buffer_allocator(const Allocator *allocator) {
        buffer_allocator = allocator;
    }

    void set_buffer_init_size(size_t size) {
        if (size == 0) {
            return;
        }
        buffer_init_size = size;
    }

    int move_fd() {
        sock_fd = SW_BAD_SOCKET;
        return socket->move_fd();
    }

    network::Socket *move_socket() {
        network::Socket *_socket = socket;
        socket = nullptr;
        return _socket;
    }

#ifdef SW_USE_OPENSSL
    bool ssl_is_available() const {
        return socket && ssl_handshaked;
    }

    SSL *get_ssl() const {
        return socket->ssl;
    }

    bool ssl_shutdown() const;
#endif

  private:
    SocketType type;
    network::Socket *socket = nullptr;
    int sock_domain = 0;
    int sock_type = 0;
    int sock_protocol = 0;
    int sock_fd = -1;

    Coroutine *read_co = nullptr;
    Coroutine *write_co = nullptr;
#ifdef SW_USE_OPENSSL
    EventType want_event = SW_EVENT_NULL;
#endif

    std::string connect_host;
    int connect_port = 0;
    int backlog = 0;

    TimerNode *read_timer = nullptr;
    TimerNode *write_timer = nullptr;

    const Allocator *buffer_allocator = nullptr;
    size_t buffer_init_size = SW_BUFFER_SIZE_BIG;
    String *read_buffer = nullptr;
    String *write_buffer = nullptr;

    EventBarrier *recv_barrier = nullptr;
    EventBarrier *send_barrier = nullptr;

#ifdef SW_USE_OPENSSL
    bool ssl_is_server = false;
    bool ssl_handshaked = false;
    std::shared_ptr<SSLContext> ssl_context = nullptr;
    std::string ssl_host_name;
    bool ssl_context_create();
    bool ssl_create(SSLContext *ssl_context);
#endif

    bool connected = false;
    bool shutdown_read = false;
    bool shutdown_write = false;

    bool zero_copy = false;

    NameResolver::Context *resolve_context_ = nullptr;
    std::function<void(Socket *)> dtor_;

    Socket(network::Socket *sock, const Socket *server_sock);

    static void timer_callback(Timer *timer, TimerNode *tnode);
    static int readable_event_callback(Reactor *reactor, Event *event);
    static int writable_event_callback(Reactor *reactor, Event *event);
    static int error_event_callback(Reactor *reactor, Event *event);

    void init_sock_type(SocketType _type);
    bool init_sock();
    bool init_reactor_socket(int fd);

    void check_return_value(ssize_t retval) {
        if (retval >= 0) {
            set_err(0);
        } else if (errCode == 0) {
            set_err(errno);
        }
    }

    void init_options() {
        if (socket->is_tcp()) {
            set_option(IPPROTO_TCP, TCP_NODELAY, 1);
        }
        if (socket->is_udp()) {
            socket->set_buffer_size(network::Socket::default_buffer_size);
        }
        protocol.package_length_type = 'N';
        protocol.package_length_size = 4;
        protocol.package_length_offset = 0;
        protocol.package_body_offset = 0;
        protocol.package_max_length = SW_INPUT_BUFFER_SIZE;
    }

    bool add_event(const EventType event);
    bool wait_event(const EventType event, const void **__buf = nullptr, size_t __n = 0);

    ssize_t recv_packet_with_length_protocol();
    ssize_t recv_packet_with_eof_protocol();

    bool is_available(const EventType event) {
        if (event != SW_EVENT_NULL) {
            check_bound_co(event);
        }
        if (sw_unlikely(is_closed())) {
            set_err(EBADF);
            return false;
        }
        if (sw_unlikely(socket->close_wait)) {
            set_err(SW_ERROR_CO_SOCKET_CLOSE_WAIT);
            return false;
        }
        return true;
    }

    bool socks5_handshake();

    const std::string &get_http_proxy_host_name() const {
#ifdef SW_USE_OPENSSL
        if (ssl_context && !ssl_context->tls_host_name.empty()) {
            return ssl_context->tls_host_name;
        }
#endif
        return http_proxy->target_host;
    }

    bool http_proxy_handshake();

    class TimerController {
      public:
        TimerController(TimerNode **_timer_pp, double _timeout, Socket *_socket, TimerCallback _callback)
            : timer_pp(_timer_pp), timeout(_timeout), socket_(_socket), callback(std::move(_callback)) {}
        bool start();
        ~TimerController();

      private:
        bool enabled = false;
        TimerNode **timer_pp;
        double timeout;
        Socket *socket_;
        TimerCallback callback;
    };

  public:
    class TimeoutSetter {
      public:
        TimeoutSetter(Socket *socket, double _timeout, const TimeoutType _type);
        ~TimeoutSetter();

      protected:
        Socket *socket_;
        double timeout;
        TimeoutType type;
        double original_timeout[sizeof(timeout_type_list)] = {};
    };

    class TimeoutController : public TimeoutSetter {
      public:
        TimeoutController(Socket *_socket, double _timeout, const TimeoutType _type)
            : TimeoutSetter(_socket, _timeout, _type) {}
        bool has_timedout(TimeoutType _type);

      protected:
        double startup_time = 0;
    };
};

class ProtocolSwitch {
    bool ori_open_eof_check;
    bool ori_open_length_check;
    Protocol ori_protocol;
    Socket *socket_;

  public:
    explicit ProtocolSwitch(Socket *socket) {
        ori_open_eof_check = socket->open_eof_check;
        ori_open_length_check = socket->open_length_check;
        ori_protocol = socket->protocol;
        socket_ = socket;
    }

    ~ProtocolSwitch() {
        /* revert protocol settings */
        socket_->open_eof_check = ori_open_eof_check;
        socket_->open_length_check = ori_open_length_check;
        socket_->protocol = ori_protocol;
    }
};

std::vector<std::string> dns_lookup(const char *domain, int family = AF_INET, double timeout = 2.0);
std::vector<std::string> dns_lookup_impl_with_socket(const char *domain, int family, double timeout);
#ifdef SW_USE_CARES
std::vector<std::string> dns_lookup_impl_with_cares(const char *domain, int family, double timeout);
#endif
std::string get_ip_by_hosts(const std::string &domain);
//-------------------------------------------------------------------------------
}  // namespace coroutine
}  // namespace swoole

std::shared_ptr<swoole::coroutine::Socket> swoole_coroutine_get_socket_object(int sockfd);
