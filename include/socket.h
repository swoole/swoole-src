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

#include "swoole.h"
#include "coroutine.h"
#include "connection.h"
#include "socks5.h"
#include <string>

namespace swoole
{
class Socket
{
public:
    enum timer_levels
    {
        TIMER_LV_NORMAL,
        TIMER_LV_MULTI,
        TIMER_LV_PACKET,
        TIMER_LV_GLOBAL
    };

    swConnection *socket = nullptr;
    enum swSocket_type type;
    int sock_domain = 0;
    int sock_type = 0;
    int sock_protocol = 0;
    int backlog = 0;
    int errCode = 0;
    const char *errMsg = "";

    bool open_length_check = false;
    bool open_eof_check = false;
    bool http2 = false;

    swProtocol protocol = {0};
    swString *read_buffer = nullptr;
    swString *write_buffer = nullptr;
    swSocketAddress bind_address_info = {{}, 0};

    struct _swSocks5 *socks5_proxy = nullptr;
    struct _http_proxy* http_proxy = nullptr;

#ifdef SW_USE_OPENSSL
    bool open_ssl = false;
    swSSL_option ssl_option = {0};
#endif

    Socket(int domain = AF_INET, int type = SOCK_STREAM, int protocol = 0);
    Socket(enum swSocket_type type = SW_SOCK_TCP);
    Socket(std::string uri, int port = 0);
    Socket(int _fd, Socket *sock);
    Socket(int _fd, enum swSocket_type _type);
    ~Socket();
    void set_timer(timer_levels _timer_level = TIMER_LV_NORMAL, double _timeout = 0);
    void del_timer(timer_levels _timer_level = TIMER_LV_NORMAL);
    bool connect(std::string _host = "", int _port = 0, int flags = 0);
    bool connect(const struct sockaddr *addr, socklen_t addrlen);
    bool shutdown(int how = SHUT_RDWR);
    bool close();
    bool is_connect();
    bool check_liveness();
    ssize_t peek(void *__buf, size_t __n);
    ssize_t recv(void *__buf, size_t __n);
    ssize_t read(void *__buf, size_t __n);
    ssize_t write(const void *__buf, size_t __n);
    ssize_t send(const void *__buf, size_t __n);
    ssize_t sendmsg(const struct msghdr *msg, int flags);
    ssize_t recvmsg(struct msghdr *msg, int flags);
    ssize_t recv_all(void *__buf, size_t __n);
    ssize_t send_all(const void *__buf, size_t __n);
    ssize_t recv_packet();
    Socket* accept();
    bool bind(std::string address, int port = 0);
    bool listen(int backlog = 0);
    bool sendfile(char *filename, off_t offset, size_t length);
    ssize_t sendto(char *address, int port, char *data, int len);
    ssize_t recvfrom(void *__buf, size_t __n);
    ssize_t recvfrom(void *__buf, size_t __n, struct sockaddr *_addr, socklen_t *_socklen);
#ifdef SW_USE_OPENSSL
    bool ssl_handshake();
    int ssl_verify(bool allow_self_signed);
    bool ssl_accept();
#endif

    static inline enum swSocket_type get_type(int domain, int type, int protocol)
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

    inline int get_fd()
    {
        return socket ? socket->fd : -1;
    }

    inline long has_bound()
    {
        return coroutine ? coroutine->get_cid() : 0;
    }

    inline void set_err(int e)
    {
        errCode = errno = e;
        errMsg = e ? strerror(e) : "";
    }

    inline void set_err(int e, const char *s)
    {
        errCode = errno = e;
        errMsg = s;
    }

    inline void set_err(enum swErrorCode e)
    {
        errCode = errno = e;
        errMsg = swstrerror(e);
    }

    inline double get_timeout()
    {
        return timeout;
    }

    inline void set_timeout(double timeout)
    {
        if (timeout == 0)
        {
            return;
        }
        this->timeout = timeout;
    }

    inline void set_timeout(struct timeval *timeout)
    {
        set_timeout((double) timeout->tv_sec + ((double) timeout->tv_usec / 1000 / 1000));
    }

    inline bool set_tcp_nodelay(int value)
    {
        if (!(type == SW_SOCK_TCP || type == SW_SOCK_TCP6))
        {
            return false;
        }
        if (setsockopt(get_fd(), IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) < 0)
        {
            swSysError("setsockopt(%d, TCP_NODELAY) failed.", get_fd());
            return false;
        }
        return true;
    }

    inline swString* get_read_buffer()
    {
        if (unlikely(!read_buffer))
        {
            read_buffer = swString_new(SW_BUFFER_SIZE_STD);
        }
        return read_buffer;
    }

    inline swString* get_write_buffer()
    {
        if (unlikely(!write_buffer))
        {
            write_buffer = swString_new(SW_BUFFER_SIZE_STD);
        }
        return write_buffer;
    }

protected:
    Coroutine* coroutine = nullptr;
    swReactor *reactor = nullptr;

    std::string host;
    int port = 0;
    std::string bind_address;
    int bind_port = 0;
    timer_levels timer_level = TIMER_LV_NORMAL;
    swTimer_node *timer = nullptr;
    double timeout = -1;

    bool shutdown_read = false;
    bool shutdown_write = false;
#ifdef SW_USE_OPENSSL
    SSL_CTX *ssl_context = nullptr;
#endif

    static void timer_callback(swTimer *timer, swTimer_node *tnode);
    static int event_callback(swReactor *reactor, swEvent *event);

    bool socks5_handshake();
    bool http_proxy_handshake();

    inline void yield()
    {
        Coroutine *co = Coroutine::get_current();
        if (unlikely(!co))
        {
            swError("Socket::yield() must be called in the coroutine.");
        }
        set_err(0);
        set_timer();
        coroutine = co;
        co->yield();
        coroutine = nullptr;
        del_timer();
    }

    inline void resume()
    {
        coroutine->resume();
    }

    inline void init_members()
    {
        protocol.package_length_type = 'N';
        protocol.package_length_size = 4;
        protocol.package_body_offset = 0;
        protocol.package_max_length = SW_BUFFER_INPUT_SIZE;
    }

    inline void init_sock_type(enum swSocket_type _type)
    {
        type = _type;
        switch (type)
        {
        case SW_SOCK_TCP6:
            sock_domain = AF_INET6;
            sock_type = SOCK_STREAM;
            break;
        case SW_SOCK_UNIX_STREAM:
            sock_domain = AF_UNIX;
            sock_type = SOCK_STREAM;
            break;
        case SW_SOCK_UDP:
            sock_domain = AF_INET;
            sock_type = SOCK_DGRAM;
            break;
        case SW_SOCK_UDP6:
            sock_domain = AF_INET6;
            sock_type = SOCK_DGRAM;
            break;
        case SW_SOCK_UNIX_DGRAM:
            sock_domain = AF_UNIX;
            sock_type = SOCK_DGRAM;
            break;
        case SW_SOCK_TCP:
        default:
            sock_domain = AF_INET;
            sock_type = SOCK_STREAM;
            break;
        }
    }

    inline void init_sock();

    inline void init_sock(int _fd);

    inline bool is_available(bool allow_cross_co = false)
    {
        long cid = has_bound();
        if (unlikely(!allow_cross_co && cid))
        {
            swoole_error_log(
                SW_LOG_ERROR, SW_ERROR_CO_HAS_BEEN_BOUND,
                "Socket#%d has already been bound to another coroutine#%ld, "
                "reading or writing of the same socket in multiple coroutines at the same time is not allowed.\n",
                socket->fd, cid
            );
            set_err(SW_ERROR_CO_HAS_BEEN_BOUND);
            exit(255);
        }
        if (unlikely(socket->closed))
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKET_CLOSED, "Socket#%d belongs to coroutine#%ld has already been closed.", socket->fd, Coroutine::get_current_cid());
            set_err(ECONNRESET);
            return false;
        }
        return true;
    }

    inline bool should_be_break()
    {
        switch (errCode)
        {
        case ETIMEDOUT:
        case ECANCELED:
            return true;
        default:
            return false;
        }
    }

    inline bool wait_event(int event)
    {
        if (reactor->add(reactor, socket->fd, SW_FD_CORO_SOCKET | event) < 0)
        {
            set_err(errno);
            return false;
        }
        return true;
    }

    inline bool wait_readable()
    {
#ifdef SW_USE_OPENSSL
        if (socket->ssl && socket->ssl_want_write)
        {
            if (unlikely(!is_available() || !wait_event(SW_EVENT_WRITE)))
            {
                return false;
            }
        }
        else
#endif
        if (unlikely(!wait_event(SW_EVENT_READ)))
        {
            return false;
        }
        yield();
        return !should_be_break();
    }

    inline void copy_to_write_buffer(const void **__buf, size_t __n)
    {
        if (*__buf != get_write_buffer()->str)
        {
            swString_clear(write_buffer);
            swString_append_ptr(write_buffer, (const char *) *__buf, __n);
            *__buf = write_buffer->str;
        }
    }

    inline bool wait_writeable(const void **__buf = nullptr, size_t __n = 0)
    {
#ifdef SW_USE_OPENSSL
        if (socket->ssl && socket->ssl_want_read)
        {
            if (unlikely(!is_available() || !wait_event(SW_EVENT_READ)))
            {
                return false;
            }
        }
        else
#endif
        if (unlikely(!wait_event(SW_EVENT_WRITE)))
        {
            return false;
        }
        if (__n > 0)
        {
            copy_to_write_buffer(__buf, __n);
        }
        yield();
        return !should_be_break();
    }
};
};
