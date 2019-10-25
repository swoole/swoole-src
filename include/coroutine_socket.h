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
  +----------------------------------------------------------------------+
*/

#pragma once

#include "coroutine.h"
#include "connection.h"
#include "socks5.h"

#include <vector>
#include <string>

#define SW_DEFAULT_SOCKET_CONNECT_TIMEOUT    1
#define SW_DEFAULT_SOCKET_READ_TIMEOUT      -1
#define SW_DEFAULT_SOCKET_WRITE_TIMEOUT     -1

namespace swoole
{
enum swTimeout_type
{
    SW_TIMEOUT_CONNECT = 1u << 1,
    SW_TIMEOUT_READ = 1u << 2,
    SW_TIMEOUT_WRITE = 1u << 3,
    SW_TIMEOUT_RDWR = SW_TIMEOUT_READ | SW_TIMEOUT_WRITE,
    SW_TIMEOUT_ALL = 0xff,
};

static constexpr enum swTimeout_type swTimeout_type_list[3] =
{
    SW_TIMEOUT_CONNECT, SW_TIMEOUT_READ, SW_TIMEOUT_WRITE
};
}

namespace swoole { namespace coroutine {
//-------------------------------------------------------------------------------
class Socket
{
public:
    static double default_connect_timeout;
    static double default_read_timeout;
    static double default_write_timeout;

    swSocket *socket = nullptr;
    int errCode = 0;
    const char *errMsg = "";

    bool open_length_check = false;
    bool open_eof_check = false;
    bool http2 = false;

    swProtocol protocol = {0};
    struct _swSocks5 *socks5_proxy = nullptr;
    struct _http_proxy* http_proxy = nullptr;

#ifdef SW_USE_OPENSSL
    bool open_ssl = false;
    swSSL_option ssl_option = {0};
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

    inline bool is_connect()
    {
        return activated && !closed;
    }

    bool check_liveness();
    ssize_t peek(void *__buf, size_t __n);
    ssize_t recv(void *__buf, size_t __n);
    ssize_t send(const void *__buf, size_t __n);
    ssize_t read(void *__buf, size_t __n);
    ssize_t write(const void *__buf, size_t __n);
    ssize_t recvmsg(struct msghdr *msg, int flags);
    ssize_t sendmsg(const struct msghdr *msg, int flags);
    ssize_t recv_all(void *__buf, size_t __n);
    ssize_t send_all(const void *__buf, size_t __n);
    ssize_t recv_packet(double timeout = 0);
    bool poll(enum swEvent_type type);
    Socket* accept(double timeout = 0);
    bool bind(std::string address, int port = 0);
    bool listen(int backlog = 0);
    bool sendfile(const char *filename, off_t offset, size_t length);
    ssize_t sendto(const char *address, int port, const void *__buf, size_t __n);
    ssize_t recvfrom(void *__buf, size_t __n);
    ssize_t recvfrom(void *__buf, size_t __n, struct sockaddr *_addr, socklen_t *_socklen);
#ifdef SW_USE_OPENSSL
    bool ssl_handshake();
    int ssl_verify(bool allow_self_signed);
    bool ssl_accept();
    bool ssl_check_context();
#endif

    static inline enum swSocket_type convert_to_type(int domain, int type, int protocol = 0)
    {
        switch (domain)
        {
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

    static inline enum swSocket_type convert_to_type(std::string &host)
    {
        if (host.compare(0, 6, "unix:/", 0, 6) == 0)
        {
            host = host.substr(sizeof("unix:") - 1);
            host.erase(0, host.find_first_not_of('/') - 1);
            return SW_SOCK_UNIX_STREAM;
        }
        else if (host.find(':') != std::string::npos)
        {
            return SW_SOCK_TCP6;
        }
        else
        {
            return SW_SOCK_TCP;
        }
    }

    static inline void init_reactor(swReactor *reactor)
    {
        swReactor_set_handler(reactor, SW_FD_CORO_SOCKET | SW_EVENT_READ, readable_event_callback);
        swReactor_set_handler(reactor, SW_FD_CORO_SOCKET | SW_EVENT_WRITE, writable_event_callback);
        swReactor_set_handler(reactor, SW_FD_CORO_SOCKET | SW_EVENT_ERROR, error_event_callback);
    }

    inline enum swSocket_type get_type()
    {
        return type;
    }

    inline int get_sock_domain()
    {
        return sock_domain;
    }

    inline int get_sock_type()
    {
        return sock_type;
    }

    inline int get_sock_protocol()
    {
        return sock_protocol;
    }

    inline int get_fd()
    {
        return sock_fd;
    }

    inline int get_bind_port()
    {
        return bind_port;
    }

    bool getsockname();
    bool getpeername();
    const char* get_ip();
    int get_port();

    inline bool has_bound(const enum swEvent_type event = SW_EVENT_RDWR)
    {
        return get_bound_co(event) != nullptr;
    }

    inline Coroutine* get_bound_co(const enum swEvent_type event)
    {
        if (event & SW_EVENT_READ)
        {
            if (read_co)
            {
                return read_co;
            }
        }
        if (event & SW_EVENT_WRITE)
        {
            if (write_co)
            {
                return write_co;
            }
        }
        return nullptr;
    }

    inline long get_bound_cid(const enum swEvent_type event = SW_EVENT_RDWR)
    {
        Coroutine *co = get_bound_co(event);
        return co ? co->get_cid() : 0;
    }

    inline void check_bound_co(const enum swEvent_type event)
    {
        long cid = get_bound_cid(event);
        if (sw_unlikely(cid))
        {
            swFatalError(
                SW_ERROR_CO_HAS_BEEN_BOUND,
                "Socket#%d has already been bound to another coroutine#%ld, "
                "%s of the same socket in coroutine#%ld at the same time is not allowed",
                sock_fd, cid,
                (event == SW_EVENT_READ ? "reading" : (event == SW_EVENT_WRITE ? "writing" :
                        (read_co && write_co ? "reading or writing" : (read_co ? "reading" : "writing")))),
                Coroutine::get_current_cid()
            );
        }
    }

    inline void set_err(int e)
    {
        errCode = errno = e;
        errMsg = e ? swoole_strerror(e) : "";
    }

    inline void set_err(int e, const char *s)
    {
        errCode = errno = e;
        errMsg = s;
    }

    /* set connect read write timeout */
    inline void set_timeout(double timeout, int type = SW_TIMEOUT_ALL)
    {
        if (timeout == 0)
        {
            return;
        }
        if (type & SW_TIMEOUT_CONNECT)
        {
            connect_timeout = timeout;
        }
        if (type & SW_TIMEOUT_READ)
        {
            read_timeout = timeout;
        }
        if (type & SW_TIMEOUT_WRITE)
        {
            write_timeout = timeout;
        }
    }

    inline void set_timeout(struct timeval *timeout, int type = SW_TIMEOUT_ALL)
    {
        set_timeout((double) timeout->tv_sec + ((double) timeout->tv_usec / 1000 / 1000), type);
    }

    inline double get_timeout(enum swTimeout_type type = SW_TIMEOUT_ALL)
    {
        SW_ASSERT_1BYTE(type);
        if (type == SW_TIMEOUT_CONNECT)
        {
            return connect_timeout;
        }
        else if (type == SW_TIMEOUT_READ)
        {
            return read_timeout;
        }
        else // if (type == SW_TIMEOUT_WRITE)
        {
            return write_timeout;
        }
    }

    inline bool set_option(int level, int optname, int optval)
    {
        if (setsockopt(sock_fd, level, optname, &optval, sizeof(optval)) != 0)
        {
            swSysWarn("setsockopt(%d, %d, %d, %d) failed", sock_fd, level, optname, optval);
            return false;
        }
        return true;
    }

    inline swString* get_read_buffer()
    {
        if (sw_unlikely(!read_buffer))
        {
            read_buffer = swString_new(SW_BUFFER_SIZE_BIG);
        }
        return read_buffer;
    }

    inline swString* get_write_buffer()
    {
        if (sw_unlikely(!write_buffer))
        {
            write_buffer = swString_new(SW_BUFFER_SIZE_BIG);
        }
        return write_buffer;
    }

#ifdef SW_USE_OPENSSL
    inline bool is_ssl_enable()
    {
        return socket && socket->ssl != NULL;
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

    double connect_timeout = default_connect_timeout;
    double read_timeout = default_read_timeout;
    double write_timeout = default_write_timeout;
    swTimer_node *read_timer = nullptr;
    swTimer_node *write_timer = nullptr;

    swString *read_buffer = nullptr;
    swString *write_buffer = nullptr;
    swSocketAddress bind_address_info = {{}, 0};

#ifdef SW_USE_OPENSSL
    std::string ssl_host_name;
    SSL_CTX *ssl_context = nullptr;
#endif

    bool activated = true;
    bool shutdown_read = false;
    bool shutdown_write = false;
    bool closed = false;

    static void timer_callback(swTimer *timer, swTimer_node *tnode);
    static int readable_event_callback(swReactor *reactor, swEvent *event);
    static int writable_event_callback(swReactor *reactor, swEvent *event);
    static int error_event_callback(swReactor *reactor, swEvent *event);

    Socket(int _fd, swSocketAddress *addr, Socket *socket);
    inline void init_sock_type(enum swSocket_type _type);
    inline bool init_sock();
    void init_reactor_socket(int fd);
    inline void init_options()
    {
        if (type == SW_SOCK_TCP || type == SW_SOCK_TCP6)
        {
            set_option(IPPROTO_TCP, TCP_NODELAY, 1);
        }
        protocol.package_length_type = 'N';
        protocol.package_length_size = 4;
        protocol.package_body_offset = 0;
        protocol.package_max_length = SW_BUFFER_INPUT_SIZE;
    }

    bool add_event(const enum swEvent_type event);
    bool wait_event(const enum swEvent_type event, const void **__buf = nullptr, size_t __n = 0);

    inline bool is_available(const enum swEvent_type event)
    {
        if (event != SW_EVENT_NULL)
        {
            check_bound_co(event);
        }
        if (sw_unlikely(closed))
        {
            set_err(ECONNRESET);
            return false;
        }
        return true;
    }

    // TODO: move to client.cc
    bool socks5_handshake();
    bool http_proxy_handshake();

    class timer_controller
    {
    public:
        timer_controller(swTimer_node **timer_pp, double timeout, Socket *sock, swTimerCallback callback) :
            timer_pp(timer_pp), timeout(timeout), socket_(sock), callback(callback)
        {
        }
        bool start()
        {
            if (timeout != 0 && !*timer_pp)
            {
                enabled = true;
                if (timeout > 0)
                {
                    *timer_pp = swoole_timer_add((long) (timeout * 1000), SW_FALSE, callback, socket_);
                    return *timer_pp != nullptr;
                }
                else // if (timeout < 0)
                {
                    *timer_pp = (swTimer_node *) -1;
                }
            }
            return true;
        }
        ~timer_controller()
        {
            if (enabled && *timer_pp)
            {
                if (*timer_pp != (swTimer_node *) -1)
                {
                    swoole_timer_del(*timer_pp);
                }
                *timer_pp = nullptr;
            }
        }
    private:
        bool enabled = false;
        swTimer_node** timer_pp;
        double timeout;
        Socket *socket_;
        swTimerCallback callback;
    };

public:
    class timeout_setter
    {
    public:
        timeout_setter(Socket *socket, double timeout, const enum swTimeout_type type) :
            socket_(socket), timeout(timeout), type(type)
        {
            if (timeout == 0)
            {
                return;
            }
            for (uint8_t i = 0; i < SW_ARRAY_SIZE(swTimeout_type_list); i++)
            {
                if (type & swTimeout_type_list[i])
                {
                    original_timeout[i] = socket->get_timeout(swTimeout_type_list[i]);
                    if (timeout != original_timeout[i])
                    {
                        socket->set_timeout(timeout, swTimeout_type_list[i]);
                    }
                }
            }
        }
        ~timeout_setter()
        {
            if (timeout == 0)
            {
                return;
            }
            for (uint8_t i = 0; i < SW_ARRAY_SIZE(swTimeout_type_list); i++)
            {
                if (type & swTimeout_type_list[i])
                {
                    if (timeout != original_timeout[i])
                    {
                        socket_->set_timeout(original_timeout[i], swTimeout_type_list[i]);
                    }
                }
            }
        }
    protected:
        Socket *socket_;
        double timeout;
        enum swTimeout_type type;
        double original_timeout[sizeof(swTimeout_type_list)] = {0};
    };

    class timeout_controller: public timeout_setter
    {
    public:
        timeout_controller(Socket *socket, double timeout, const enum swTimeout_type type) :
                timeout_setter(socket, timeout, type)
        {
        }
        inline bool has_timedout(const enum swTimeout_type type)
        {
            SW_ASSERT_1BYTE(type);
            if (timeout > 0)
            {
                if (sw_unlikely(startup_time == 0))
                {
                    startup_time = swoole_microtime();
                }
                else
                {
                    double used_time = swoole_microtime() - startup_time;
                    if (sw_unlikely(timeout - used_time < SW_TIMER_MIN_SEC))
                    {
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
std::vector<std::string> dns_lookup(const char *domain, double timeout = 2.0);
//-------------------------------------------------------------------------------
}}
