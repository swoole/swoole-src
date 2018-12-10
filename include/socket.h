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
enum socket_lock_operation
{
    SOCKET_LOCK_READ = 1U << 1,
    SOCKET_LOCK_WRITE = 1U << 2,
    SOCKET_LOCK_RW = SOCKET_LOCK_READ | SOCKET_LOCK_WRITE
};

class Socket
{
public:
    Socket(enum swSocket_type type);
    Socket(int _fd, Socket *sock);
    Socket(int _fd, enum swSocket_type _type);
    ~Socket();
    bool connect(std::string host, int port, int flags = 0);
    bool connect(const struct sockaddr *addr, socklen_t addrlen);
    bool shutdown(int how = SHUT_RDWR);
    bool close();
    ssize_t send(const void *__buf, size_t __n);
    ssize_t sendmsg(const struct msghdr *msg, int flags);
    ssize_t peek(void *__buf, size_t __n);
    ssize_t recv(void *__buf, size_t __n);
    ssize_t read(void *__buf, size_t __n);
    ssize_t write(const void *__buf, size_t __n);
    ssize_t recvmsg(struct msghdr *msg, int flags);
    ssize_t recv_all(void *__buf, size_t __n);
    ssize_t send_all(const void *__buf, size_t __n);
    ssize_t recv_packet();
    Socket* accept();
    void resume(int operation);
    void yield(int operation);
    bool bind(std::string address, int port = 0);
    std::string resolve(std::string host);
    bool listen(int backlog = 0);
    bool sendfile(char *filename, off_t offset, size_t length);
    ssize_t sendto(char *address, int port, char *data, int len);
    ssize_t recvfrom(void *__buf, size_t __n);
    ssize_t recvfrom(void *__buf, size_t __n, struct sockaddr *_addr, socklen_t *_socklen);

    inline long has_bound(socket_lock_operation type)
    {
        if ((type & SOCKET_LOCK_READ) && read_co)
        {
            return read_co->get_cid();
        }
        else if ((type & SOCKET_LOCK_WRITE) && write_co)
        {
            return write_co->get_cid();
        }
        return 0;
    }

    inline void set_timeout(double timeout, bool temp = false)
    {
        if (timeout == 0)
        {
            return;
        }
        if (temp)
        {
            _timeout_temp = timeout;
        }
        else
        {
            _timeout = timeout;
        }
    }

    inline void set_timeout(struct timeval *timeout)
    {
        set_timeout((double) timeout->tv_sec + ((double) timeout->tv_usec / 1000 / 1000));
    }

    inline swString* get_read_buffer()
    {
        if (unlikely(read_buffer == nullptr))
        {
            read_buffer = swString_new(SW_BUFFER_SIZE_STD);
        }
        return read_buffer;
    }

    inline swString* get_write_buffer()
    {
        if (unlikely(write_buffer == nullptr))
        {
            write_buffer = swString_new(SW_BUFFER_SIZE_STD);
        }
        return write_buffer;
    }

    inline void copy_to_write_buffer(const void *__buf, size_t __n)
    {
        get_write_buffer();
        swString_clear(write_buffer);
        swString_append_ptr(write_buffer, (const char *) __buf, __n);
    }

    inline int get_fd()
    {
        return socket ? socket->fd : -1;
    }

#ifdef SW_USE_OPENSSL
    bool ssl_handshake();
    int ssl_verify(bool allow_self_signed);
    bool ssl_accept();
#endif

protected:
    inline void init_members()
    {
        read_co = nullptr;
        write_co = nullptr;
        _timeout = 0;
        _timeout_temp = 0;
        _port = 0;
        errCode = 0;
        errMsg = nullptr;
        read_timer = nullptr;
        write_timer = nullptr;
        bind_port = 0;
        _backlog = 0;
        _closed = false;

        http2 = 0;
        shutdown_read = 0;
        shutdown_write = 0;
        open_length_check = 0;
        open_eof_check = 0;

        socks5_proxy = nullptr;
        http_proxy = nullptr;

        read_buffer = nullptr;
        write_buffer = nullptr;
        protocol = {0};
        bind_address_info = {{}, 0};

        protocol.package_length_type = 'N';
        protocol.package_length_size = 4;
        protocol.package_body_offset = 0;
        protocol.package_max_length = SW_BUFFER_INPUT_SIZE;

#ifdef SW_USE_OPENSSL
        open_ssl = false;
        ssl_context = NULL;
        ssl_option = {0};
#endif
    }

    inline void init_sock_type(enum swSocket_type _type)
    {
        type = _type;
        switch (type)
        {
        case SW_SOCK_TCP6:
            _sock_domain = AF_INET6;
            _sock_type = SOCK_STREAM;
            break;
        case SW_SOCK_UNIX_STREAM:
            _sock_domain = AF_UNIX;
            _sock_type = SOCK_STREAM;
            break;
        case SW_SOCK_UDP:
            _sock_domain = AF_INET;
            _sock_type = SOCK_DGRAM;
            break;
        case SW_SOCK_UDP6:
            _sock_domain = AF_INET6;
            _sock_type = SOCK_DGRAM;
            break;
        case SW_SOCK_UNIX_DGRAM:
            _sock_domain = AF_UNIX;
            _sock_type = SOCK_DGRAM;
            break;
        case SW_SOCK_TCP:
        default:
            _sock_domain = AF_INET;
            _sock_type = SOCK_STREAM;
            break;
        }
    }

    inline void init_sock(int _fd);

    inline bool wait_events(int events)
    {
        if (socket->events == 0)
        {
            if (reactor->add(reactor, socket->fd, SW_FD_CORO_SOCKET | events) < 0)
            {
                errCode = errno;
                return false;
            }
        }
        else
        {
            if (reactor->set(reactor, socket->fd, SW_FD_CORO_SOCKET | socket->events | events) < 0)
            {
                errCode = errno;
                return false;
            }
        }
        return true;
    }

    inline bool is_available(socket_lock_operation type)
    {
        long cid = has_bound(type);
        if (unlikely(cid))
        {
            swoole_error_log(
                SW_LOG_ERROR, SW_ERROR_CO_HAS_BEEN_BOUND,
                "Socket#%d has already been bound to another coroutine#%ld, "
                "reading or writing of the same socket in multiple coroutines at the same time is not allowed.\n",
                socket->fd, cid
            );
            errCode = SW_ERROR_CO_HAS_BEEN_BOUND;
            exit(255);
        }
        if (unlikely(_closed))
        {
            errCode = SW_ERROR_SOCKET_CLOSED;
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKET_CLOSED, "Socket#%d belongs to coroutine#%ld has already been closed.", socket->fd, cid);
            return false;
        }
        return true;
    }

    bool socks5_handshake();
    bool http_proxy_handshake();

public:

    swReactor *reactor;
    std::string _host;
    std::string bind_address;
    int bind_port;
    int _port;
    Coroutine* read_co;
    Coroutine* write_co;
    swTimer_node *read_timer;
    swTimer_node *write_timer;
    swConnection *socket = nullptr;
    enum swSocket_type type;
    int _sock_type;
    int _sock_domain;
    double _timeout;
    double _timeout_temp;
    int _backlog;
    bool _closed;
    int errCode;
    const char *errMsg;
    uint32_t http2 :1;
    uint32_t shutdown_read :1;
    uint32_t shutdown_write :1;
    /**
     * one package: length check
     */
    uint32_t open_length_check :1;
    uint32_t open_eof_check :1;

    swProtocol protocol;
    swString *read_buffer;
    swString *write_buffer;
    swSocketAddress bind_address_info;

    struct _swSocks5 *socks5_proxy;
    struct _http_proxy* http_proxy;

#ifdef SW_USE_OPENSSL
    bool open_ssl;
    bool ssl_wait_handshake;
    SSL_CTX *ssl_context;
    swSSL_option ssl_option;
#endif
};

static inline enum swSocket_type get_socket_type(int domain, int type, int protocol)
{
    if (domain == AF_INET)
    {
        return type == SOCK_STREAM ? SW_SOCK_TCP : SW_SOCK_UDP;
    }
    else if (domain == AF_INET6)
    {
        return type == SOCK_STREAM ? SW_SOCK_TCP6 : SW_SOCK_UDP6;
    }
    else if (domain == AF_UNIX)
    {
        return type == SOCK_STREAM ? SW_SOCK_UNIX_STREAM : SW_SOCK_UNIX_DGRAM;
    }
    else
    {
        return SW_SOCK_TCP;
    }
}

static inline enum swSocket_type get_socket_type_from_uri(std::string &uri, bool convert_to_addr = 0)
{
    if (uri.compare(0, 6, "unix:/", 0, 6) == 0)
    {
        if (convert_to_addr)
        {
            uri = uri.substr(sizeof("unix:") - 1);
            uri.erase(0, uri.find_first_not_of('/') - 1);
        }
        return SW_SOCK_UNIX_STREAM;
    }
    else if (uri.find(':') != std::string::npos)
    {
        return SW_SOCK_TCP6;
    }
    else
    {
        return SW_SOCK_TCP;
    }
}

};
