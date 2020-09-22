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

#include "swoole_api.h"
#include "swoole_coroutine.h"
#include "swoole_protocol.h"
#include "swoole_log.h"
#include "swoole_ssl.h"
#include "swoole_proxy.h"

#include <vector>

namespace swoole {
namespace coroutine {
//-------------------------------------------------------------------------------
struct EventBarrier {
    size_t n;
    size_t total_bytes;
    ssize_t retval;
    char *buf;
    bool hold;
};

class Socket {
  public:
    network::Socket *socket = nullptr;
    int errCode = 0;
    const char *errMsg = "";
    std::string errString;

    bool open_length_check = false;
    bool open_eof_check = false;
    bool http2 = false;

    Protocol protocol = {};
    Socks5Proxy *socks5_proxy = nullptr;
    HttpProxy *http_proxy = nullptr;

    enum TimeoutType {
        TIMEOUT_DNS = 1 << 0,
        TIMEOUT_CONNECT = 1 << 1,
        TIMEOUT_READ = 1 << 2,
        TIMEOUT_WRITE = 1 << 3,
        TIMEOUT_RDWR = TIMEOUT_READ | TIMEOUT_WRITE,
        TIMEOUT_ALL = TIMEOUT_DNS | TIMEOUT_CONNECT | TIMEOUT_RDWR,
    };

    static enum TimeoutType timeout_type_list[4];

#ifdef SW_USE_OPENSSL
    bool open_ssl = false;
    swSSL_option ssl_option = {};
#endif

    Socket(int domain, int type, int protocol);
    Socket(int _fd, int _domain, int _type, int _protocol);
    Socket(enum swSocket_type type = SW_SOCK_TCP);
    Socket(int _fd, enum swSocket_type _type);
    ~Socket();
    bool connect(std::string host, int port, int flags = 0);
    bool connect(const struct sockaddr *addr, socklen_t addrlen);
    bool shutdown(int how = SHUT_RDWR);
    bool cancel(const enum swEvent_type event);
    bool close();

    inline bool is_connect() {
        return connected && !closed;
    }

    bool check_liveness();
    ssize_t peek(void *__buf, size_t __n);
    ssize_t recv(void *__buf, size_t __n);
    ssize_t send(const void *__buf, size_t __n);

    inline ssize_t send(const std::string &buf) {
        return send(buf.c_str(), buf.length());
    }

    ssize_t read(void *__buf, size_t __n);
    ssize_t write(const void *__buf, size_t __n);
    ssize_t recvmsg(struct msghdr *msg, int flags);
    ssize_t sendmsg(const struct msghdr *msg, int flags);
    ssize_t recv_all(void *__buf, size_t __n);
    ssize_t send_all(const void *__buf, size_t __n);
    ssize_t recv_packet(double timeout = 0);
    ssize_t recv_with_buffer(void *__buf, size_t __n);

    inline char *pop_packet() {
        if (read_buffer->offset == 0) {
            return nullptr;
        } else {
            return read_buffer->pop(buffer_init_size);
        }
    }

    bool poll(enum swEvent_type type);
    Socket *accept(double timeout = 0);
    bool bind(std::string address, int port = 0);
    bool bind(const struct sockaddr *sa, socklen_t len);
    bool listen(int backlog = 0);
    bool sendfile(const char *filename, off_t offset, size_t length);
    ssize_t sendto(const std::string &host, int port, const void *__buf, size_t __n);
    ssize_t recvfrom(void *__buf, size_t __n);
    ssize_t recvfrom(void *__buf, size_t __n, struct sockaddr *_addr, socklen_t *_socklen);
#ifdef SW_USE_OPENSSL
    bool ssl_check_context();
    bool ssl_handshake();
    bool ssl_verify(bool allow_self_signed);
    std::string ssl_get_peer_cert();
#endif

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

    static inline void init_reactor(swReactor *reactor) {
        reactor->set_handler(SW_FD_CORO_SOCKET | SW_EVENT_READ, readable_event_callback);
        reactor->set_handler(SW_FD_CORO_SOCKET | SW_EVENT_WRITE, writable_event_callback);
        reactor->set_handler(SW_FD_CORO_SOCKET | SW_EVENT_ERROR, error_event_callback);
    }

    inline enum swSocket_type get_type() {
        return type;
    }

    inline int get_sock_domain() {
        return sock_domain;
    }

    inline int get_sock_type() {
        return sock_type;
    }

    inline int get_sock_protocol() {
        return sock_protocol;
    }

    inline int get_fd() {
        return sock_fd;
    }

    inline int get_bind_port() {
        return bind_port;
    }

    bool getsockname(swoole::network::Address *sa);
    bool getpeername(swoole::network::Address *sa);

    inline const char *get_ip() {
        return socket->info.get_ip();
    }

    inline int get_port() {
        return socket->info.get_port();
    }

    inline bool has_bound(const enum swEvent_type event = SW_EVENT_RDWR) {
        return get_bound_co(event) != nullptr;
    }

    inline Coroutine *get_bound_co(const enum swEvent_type event) {
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

    inline long get_bound_cid(const enum swEvent_type event = SW_EVENT_RDWR) {
        Coroutine *co = get_bound_co(event);
        return co ? co->get_cid() : 0;
    }

    inline void check_bound_co(const enum swEvent_type event) {
        long cid = get_bound_cid(event);
        if (sw_unlikely(cid)) {
            swFatalError(SW_ERROR_CO_HAS_BEEN_BOUND,
                         "Socket#%d has already been bound to another coroutine#%ld, "
                         "%s of the same socket in coroutine#%ld at the same time is not allowed",
                         sock_fd,
                         cid,
                         (event == SW_EVENT_READ
                              ? "reading"
                              : (event == SW_EVENT_WRITE ? "writing"
                                                         : (read_co && write_co ? "reading or writing"
                                                                                : (read_co ? "reading" : "writing")))),
                         Coroutine::get_current_cid());
        }
    }

    inline void set_err(int e) {
        errCode = errno = e;
        errMsg = e ? swoole_strerror(e) : "";
    }

    inline void set_err(int e, const char *s) {
        errCode = errno = e;
        errMsg = s;
    }

    inline void set_err(int e, std::string s) {
        errCode = errno = e;
        errString = s;
        errMsg = errString.c_str();
    }

    /* set connect read write timeout */
    inline void set_timeout(double timeout, int type = TIMEOUT_ALL) {
        if (timeout == 0) {
            return;
        }
        if (type & TIMEOUT_DNS) {
            dns_timeout = timeout;
        }
        if (type & TIMEOUT_CONNECT) {
            connect_timeout = timeout;
        }
        if (type & TIMEOUT_READ) {
            read_timeout = timeout;
        }
        if (type & TIMEOUT_WRITE) {
            write_timeout = timeout;
        }
    }

    inline void set_timeout(struct timeval *timeout, int type = TIMEOUT_ALL) {
        set_timeout((double) timeout->tv_sec + ((double) timeout->tv_usec / 1000 / 1000), type);
    }

    inline double get_timeout(enum TimeoutType type = TIMEOUT_ALL) {
        SW_ASSERT_1BYTE(type);
        if (type == TIMEOUT_DNS) {
            return dns_timeout;
        } else if (type == TIMEOUT_CONNECT) {
            return connect_timeout;
        } else if (type == TIMEOUT_READ) {
            return read_timeout;
        } else  // if (type == TIMEOUT_WRITE)
        {
            return write_timeout;
        }
    }

    inline bool set_option(int level, int optname, int optval) {
        if (setsockopt(sock_fd, level, optname, &optval, sizeof(optval)) != 0) {
            swSysWarn("setsockopt(%d, %d, %d, %d) failed", sock_fd, level, optname, optval);
            return false;
        }
        return true;
    }

    inline String *get_read_buffer() {
        if (sw_unlikely(!read_buffer)) {
            read_buffer = swoole::make_string(SW_BUFFER_SIZE_BIG, buffer_allocator);
            if (!read_buffer) {
                throw std::bad_alloc();
            }
        }
        return read_buffer;
    }

    inline String *get_write_buffer() {
        if (sw_unlikely(!write_buffer)) {
            write_buffer = swoole::make_string(SW_BUFFER_SIZE_BIG, buffer_allocator);
            if (!write_buffer) {
                throw std::bad_alloc();
            }
        }
        return write_buffer;
    }

    inline String *pop_read_buffer() {
        if (sw_unlikely(!read_buffer)) {
            return nullptr;
        }
        auto tmp = read_buffer;
        read_buffer = nullptr;
        return tmp;
    }

    inline String *pop_write_buffer() {
        if (sw_unlikely(!write_buffer)) {
            return nullptr;
        }
        auto tmp = write_buffer;
        write_buffer = nullptr;
        return tmp;
    }

    inline void set_zero_copy(bool enable) {
        zero_copy = enable;
    }

    inline void set_buffer_allocator(swAllocator *allocator) {
        buffer_allocator = allocator;
    }

    inline void set_buffer_init_size(size_t size) {
        if (size == 0) {
            return;
        }
        buffer_init_size = size;
    }

#ifdef SW_USE_OPENSSL
    inline bool is_ssl_enable() {
        return socket && ssl_handshaked;
    }

    bool ssl_shutdown();
#endif

  private:
    enum swSocket_type type;
    int sock_domain = 0;
    int sock_type = 0;
    int sock_protocol = 0;
    int sock_fd = -1;

    Coroutine *read_co = nullptr;
    Coroutine *write_co = nullptr;
#ifdef SW_USE_OPENSSL
    enum swEvent_type want_event = SW_EVENT_NULL;
#endif

    std::string connect_host;
    int connect_port = 0;

    std::string bind_address;
    int bind_port = 0;
    int backlog = 0;

    double dns_timeout = network::Socket::default_dns_timeout;
    double connect_timeout = network::Socket::default_connect_timeout;
    double read_timeout = network::Socket::default_read_timeout;
    double write_timeout = network::Socket::default_write_timeout;
    TimerNode *read_timer = nullptr;
    TimerNode *write_timer = nullptr;

    const swAllocator *buffer_allocator = nullptr;
    size_t buffer_init_size = SW_BUFFER_SIZE_BIG;
    String *read_buffer = nullptr;
    String *write_buffer = nullptr;
    network::Address bind_address_info = {};

    EventBarrier recv_barrier = {};
    EventBarrier send_barrier = {};

#ifdef SW_USE_OPENSSL
    bool ssl_is_server = false;
    bool ssl_handshaked = false;
    SSL_CTX *ssl_context = nullptr;
    std::string ssl_host_name;
    bool ssl_create(SSL_CTX *ssl_context);
#endif

    bool connected = false;
    bool shutdown_read = false;
    bool shutdown_write = false;
    bool closed = false;

    bool zero_copy = false;

    Socket(network::Socket *sock, Socket *socket);

    static void timer_callback(swTimer *timer, TimerNode *tnode);
    static int readable_event_callback(swReactor *reactor, swEvent *event);
    static int writable_event_callback(swReactor *reactor, swEvent *event);
    static int error_event_callback(swReactor *reactor, swEvent *event);

    inline void init_sock_type(enum swSocket_type _type);
    inline bool init_sock();
    bool init_reactor_socket(int fd);

    inline void init_options() {
        if (type == SW_SOCK_TCP || type == SW_SOCK_TCP6) {
            set_option(IPPROTO_TCP, TCP_NODELAY, 1);
        }
        protocol.package_length_type = 'N';
        protocol.package_length_size = 4;
        protocol.package_length_offset = 0;
        protocol.package_body_offset = 0;
        protocol.package_max_length = SW_INPUT_BUFFER_SIZE;
    }

    bool add_event(const enum swEvent_type event);
    bool wait_event(const enum swEvent_type event, const void **__buf = nullptr, size_t __n = 0);

    ssize_t recv_packet_with_length_protocol();
    ssize_t recv_packet_with_eof_protocol();

    inline bool is_available(const enum swEvent_type event) {
        if (event != SW_EVENT_NULL) {
            check_bound_co(event);
        }
        if (sw_unlikely(closed)) {
            set_err(ECONNRESET);
            return false;
        }
        return true;
    }

    bool socks5_handshake();
    bool http_proxy_handshake();

    class TimerController {
      public:
        TimerController(TimerNode **timer_pp, double timeout, Socket *sock, TimerCallback callback)
            : timer_pp(timer_pp), timeout(timeout), socket_(sock), callback(callback) {}
        bool start() {
            if (timeout != 0 && !*timer_pp) {
                enabled = true;
                if (timeout > 0) {
                    *timer_pp = swoole_timer_add((long) (timeout * 1000), false, callback, socket_);
                    return *timer_pp != nullptr;
                } else  // if (timeout < 0)
                {
                    *timer_pp = (TimerNode *) -1;
                }
            }
            return true;
        }
        ~TimerController() {
            if (enabled && *timer_pp) {
                if (*timer_pp != (TimerNode *) -1) {
                    swoole_timer_del(*timer_pp);
                }
                *timer_pp = nullptr;
            }
        }

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
        TimeoutSetter(Socket *socket, double timeout, const enum TimeoutType type)
            : socket_(socket), timeout(timeout), type(type) {
            if (timeout == 0) {
                return;
            }
            for (uint8_t i = 0; i < SW_ARRAY_SIZE(timeout_type_list); i++) {
                if (type & timeout_type_list[i]) {
                    original_timeout[i] = socket->get_timeout(timeout_type_list[i]);
                    if (timeout != original_timeout[i]) {
                        socket->set_timeout(timeout, timeout_type_list[i]);
                    }
                }
            }
        }
        ~TimeoutSetter() {
            if (timeout == 0) {
                return;
            }
            for (uint8_t i = 0; i < SW_ARRAY_SIZE(timeout_type_list); i++) {
                if (type & timeout_type_list[i]) {
                    if (timeout != original_timeout[i]) {
                        socket_->set_timeout(original_timeout[i], timeout_type_list[i]);
                    }
                }
            }
        }

      protected:
        Socket *socket_;
        double timeout;
        enum TimeoutType type;
        double original_timeout[sizeof(timeout_type_list)] = {};
    };

    class timeout_controller : public TimeoutSetter {
      public:
        timeout_controller(Socket *socket, double timeout, const enum TimeoutType type)
            : TimeoutSetter(socket, timeout, type) {}
        inline bool has_timedout(const enum TimeoutType type) {
            SW_ASSERT_1BYTE(type);
            if (timeout > 0) {
                if (sw_unlikely(startup_time == 0)) {
                    startup_time = swoole_microtime();
                } else {
                    double used_time = swoole_microtime() - startup_time;
                    if (sw_unlikely(timeout - used_time < SW_TIMER_MIN_SEC)) {
                        socket_->set_err(ETIMEDOUT);
                        return true;
                    }
                    socket_->set_timeout(timeout - used_time, type);
                }
            }
            return false;
        }

      protected:
        double startup_time = 0;
    };
};

class ProtocolSwitch {
  private:
    bool ori_open_eof_check;
    bool ori_open_length_check;
    Protocol ori_protocol;
    Socket *socket_;
  public:
    ProtocolSwitch(Socket *socket) {
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

std::vector<std::string> dns_lookup(const char *domain, double timeout = 2.0);
//-------------------------------------------------------------------------------
}  // namespace coroutine
}  // namespace swoole

swoole::coroutine::Socket *swoole_coroutine_get_socket_object(int sockfd);
