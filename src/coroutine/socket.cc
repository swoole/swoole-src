#include "socket.h"
#include "coroutine.h"
#include "async.h"
#include "buffer.h"
#include "base64.h"

#include <string>
#include <iostream>
#include <sys/stat.h>

using namespace swoole;
using namespace std;

void Socket::timer_callback(swTimer *timer, swTimer_node *tnode)
{
    Socket *sock = (Socket *) tnode->data;
    swTraceLog(SW_TRACE_SOCKET, "socket[%d] timeout", sock->socket->fd);
    sock->set_err(ETIMEDOUT);
    sock->reactor->del(sock->reactor, sock->socket->fd);
    sock->timer = NULL;
    sock->resume();
}

int Socket::event_callback(swReactor *reactor, swEvent *event)
{
    Socket *sock = (Socket *) event->socket->object;
    sock->reactor->del(sock->reactor, event->fd);
    sock->resume();
    return SW_OK;
}

bool Socket::socks5_handshake()
{
    swSocks5 *ctx = socks5_proxy;
    char *buf = ctx->buf;
    int n;

    /**
     * handshake
     */
    swSocks5_pack(buf, socks5_proxy->username == NULL ? 0x00 : 0x02);
    socks5_proxy->state = SW_SOCKS5_STATE_HANDSHAKE;
    if (send(buf, 3) <= 0)
    {
        return false;
    }
    n = recv(buf, sizeof(ctx->buf));
    if (n <= 0)
    {
        return false;
    }
    uchar version = buf[0];
    uchar method = buf[1];
    if (version != SW_SOCKS5_VERSION_CODE)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported.");
        return SW_ERR;
    }
    if (method != ctx->method)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_METHOD, "SOCKS authentication method not supported.");
        return SW_ERR;
    }
    //authenticate request
    if (method == SW_SOCKS5_METHOD_AUTH)
    {
        buf[0] = 0x01;
        buf[1] = ctx->l_username;

        buf += 2;
        memcpy(buf, ctx->username, ctx->l_username);
        buf += ctx->l_username;
        buf[0] = ctx->l_password;
        memcpy(buf + 1, ctx->password, ctx->l_password);

        ctx->state = SW_SOCKS5_STATE_AUTH;

        if (send(ctx->buf, ctx->l_username + ctx->l_password + 3) < 0)
        {
            return false;
        }

        n = recv(buf, sizeof(ctx->buf));
        if (n <= 0)
        {
            return false;
        }

        uchar version = buf[0];
        uchar status = buf[1];
        if (version != 0x01)
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported.");
            return false;
        }
        if (status != 0)
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_AUTH_FAILED,
                    "SOCKS username/password authentication failed.");
            return false;
        }
        goto send_connect_request;
    }
    //send connect request
    else
    {
        send_connect_request: buf[0] = SW_SOCKS5_VERSION_CODE;
        buf[1] = 0x01;
        buf[2] = 0x00;

        ctx->state = SW_SOCKS5_STATE_CONNECT;

        if (ctx->dns_tunnel)
        {
            buf[3] = 0x03;
            buf[4] = ctx->l_target_host;
            buf += 5;
            memcpy(buf, ctx->target_host, ctx->l_target_host);
            sw_free(ctx->target_host);
            buf += ctx->l_target_host;
            *(uint16_t *) buf = htons(ctx->target_port);

            if (send(ctx->buf, ctx->l_target_host + 7) < 0)
            {
                return false;
            }
        }
        else
        {
            buf[3] = 0x01;
            buf += 4;
            *(uint32_t *) buf = htons(ctx->l_target_host);
            buf += 4;
            *(uint16_t *) buf = htons(ctx->target_port);

            if (send(ctx->buf, ctx->l_target_host + 7) < 0)
            {
                return false;
            }
        }

        /**
         * response
         */
        buf = ctx->buf;
        n = recv(buf, sizeof(ctx->buf));
        if (n <= 0)
        {
            return false;
        }

        uchar version = buf[0];
        if (version != SW_SOCKS5_VERSION_CODE)
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported.");
            return false;
        }
        uchar result = buf[1];
#if 0
        uchar reg = buf[2];
        uchar type = buf[3];
        uint32_t ip = *(uint32_t *) (buf + 4);
        uint16_t port = *(uint16_t *) (buf + 8);
#endif
        if (result == 0)
        {
            ctx->state = SW_SOCKS5_STATE_READY;
            return true;
        }
        else
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_SERVER_ERROR, "Socks5 server error, reason :%s.",
                    swSocks5_strerror(result));
            return false;
        }
    }
}

bool Socket::http_proxy_handshake()
{
    //CONNECT
    int n;
    if (http_proxy->password)
    {
        char auth_buf[256];
        char encode_buf[512];
        n = snprintf(
            auth_buf, sizeof(auth_buf), "%*s:%*s",
            http_proxy->l_user, http_proxy->user,
            http_proxy->l_password, http_proxy->password
        );
        swBase64_encode((unsigned char *) auth_buf, n, encode_buf);
        n = snprintf(
            http_proxy->buf, sizeof(http_proxy->buf),
            "CONNECT %*s:%d HTTP/1.1\r\nProxy-Authorization:Basic %s\r\n\r\n",
            http_proxy->l_target_host, http_proxy->target_host, http_proxy->target_port, encode_buf
        );
    }
    else
    {
        n = snprintf(
            http_proxy->buf, sizeof(http_proxy->buf),
            "CONNECT %*s:%d HTTP/1.1\r\n\r\n",
            http_proxy->l_target_host, http_proxy->target_host, http_proxy->target_port
        );
    }

    if (send(http_proxy->buf, n) <= 0)
    {
        return false;
    }

    n = recv(http_proxy->buf, sizeof(http_proxy->buf));
    if (n <= 0)
    {
        return false;
    }
    char *buf = http_proxy->buf;
    int len = n;
    int state = 0;
    char *p = buf;
    for (p = buf; p < buf + len; p++)
    {
        if (state == 0)
        {
            if (strncasecmp(p, "HTTP/1.1", 8) == 0 || strncasecmp(p, "HTTP/1.0", 8) == 0)
            {
                state = 1;
                p += 8;
            }
            else
            {
                break;
            }
        }
        else if (state == 1)
        {
            if (isspace(*p))
            {
                continue;
            }
            else
            {
                if (strncasecmp(p, "200", 3) == 0)
                {
                    state = 2;
                    p += 3;
                }
                else
                {
                    break;
                }
            }
        }
        else if (state == 2)
        {
            if (isspace(*p))
            {
                continue;
            }
            else
            {
                if (strncasecmp(p, "Connection established", sizeof("Connection established") - 1) == 0)
                {
                    return true;
                }
                else
                {
                    break;
                }
            }
        }
    }
    return false;
}

static inline int socket_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    int retval;
    while (1)
    {
        retval = ::connect(fd, addr, len);
        if (retval < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
        }
        break;
    }
    return retval;
}

void Socket::init_sock()
{
#ifdef SOCK_CLOEXEC
    int _fd = ::socket(sock_domain, sock_type | SOCK_CLOEXEC, sock_protocol);
#else
    int _fd = ::socket(sock_domain, sock_type, sock_protocol);
#endif
    if (unlikely(_fd < 0))
    {
        swWarn("Socket construct failed. Error: %s[%d]", strerror(errno), errno);
        return;
    }
    init_sock(_fd);
}

void Socket::init_sock(int _fd)
{
    if (swIsMaster() && SwooleTG.type == SW_THREAD_REACTOR)
    {
        reactor = SwooleTG.reactor;
    }
    else
    {
        reactor = SwooleG.main_reactor;
    }

    socket = swReactor_get(reactor, _fd);
    bzero(socket, sizeof(swConnection));
    socket->fd = _fd;
    socket->object = this;
    socket->socket_type = type;
    socket->removed = 1;
    socket->fdtype = SW_FD_CORO_SOCKET;

    swSetNonBlock(socket->fd);
    if (!swReactor_handle_isset(reactor, SW_FD_CORO_SOCKET))
    {
        reactor->setHandle(reactor, SW_FD_CORO_SOCKET | SW_EVENT_READ, event_callback);
        reactor->setHandle(reactor, SW_FD_CORO_SOCKET | SW_EVENT_WRITE, event_callback);
        reactor->setHandle(reactor, SW_FD_CORO_SOCKET | SW_EVENT_ERROR, event_callback);
    }
}

Socket::Socket(int _domain, int _type, int _protocol) :
        sock_domain(_domain), sock_type(_type), sock_protocol(_protocol)
{
    init_members();
    type = get_type(_domain, _type, _protocol);
    init_sock();
}

Socket::Socket(enum swSocket_type _type)
{
    init_members();
    init_sock_type(_type);
    init_sock();
}

Socket::Socket(int _fd, enum swSocket_type _type)
{
    init_members();
    init_sock_type(_type);
    init_sock(_fd);
    socket->active = 1;
}

Socket::Socket(int _fd, Socket *server_sock)
{
    init_members();

    sock_domain = server_sock->sock_domain;
    sock_type = server_sock->sock_type;

    reactor = server_sock->reactor;
    socket = swReactor_get(reactor, _fd);
    bzero(socket, sizeof(swConnection));
    socket->fd = _fd;
    socket->object = this;
    socket->socket_type = server_sock->type;
    socket->removed = 1;
    socket->active = 1;
    socket->fdtype = SW_FD_CORO_SOCKET;
}

void Socket::set_timer(timer_levels _timer_level, double _timeout)
{
    if (_timeout == 0)
    {
        _timeout = timeout;
    }
    if (!timer && _timeout > 0)
    {
        timer_level = _timer_level;
        timer = swTimer_add(&SwooleG.timer, (long) (_timeout * 1000), 0, this, timer_callback);
    }
}

void Socket::del_timer(timer_levels _timer_level)
{
    if (timer && _timer_level == timer_level)
    {
        swTimer_del(&SwooleG.timer, timer);
        timer = nullptr;
    }
}

bool Socket::connect(const struct sockaddr *addr, socklen_t addrlen)
{
    if (unlikely(!is_available()))
    {
        return false;
    }
    int retval = socket_connect(socket->fd, addr, addrlen);
    if (retval == -1)
    {
        if (errno != EINPROGRESS)
        {
            set_err(errno);
            return false;
        }
        if (!wait_writeable())
        {
            return false;
        }
        //Connection is closed
        if (socket->closed)
        {
            set_err(ECONNABORTED);
            return false;
        }
        socklen_t len = sizeof(errCode);
        if (getsockopt(socket->fd, SOL_SOCKET, SO_ERROR, &errCode, &len) < 0 || errCode != 0)
        {
            set_err(errCode);
            return false;
        }
    }
    set_err(0);
    socket->active = 1;
    return true;
}

bool Socket::connect(string _host, int _port, int flags)
{
    if (unlikely(!is_available()))
    {
        return false;
    }

    if (socks5_proxy)
    {
        //enable socks5 proxy
        socks5_proxy->target_host = sw_strndup((char *) _host.c_str(), _host.size());
        socks5_proxy->l_target_host = _host.size();
        socks5_proxy->target_port = _port;

        _host = socks5_proxy->host;
        _port = socks5_proxy->port;
    }
    else if (http_proxy)
    {
        //enable http proxy
        http_proxy->target_host = sw_strndup((char *) _host.c_str(), _host.size());
        http_proxy->l_target_host = _host.size();
        http_proxy->target_port = _port;

        _host = http_proxy->proxy_host;
        _port = http_proxy->proxy_port;
    }

    if (sock_domain == AF_INET6 || sock_domain == AF_INET)
    {
        if (_port == -1)
        {
            swWarn("Socket of type AF_INET/AF_INET6 requires port argument");
            return false;
        }
        else if (_port == 0 || _port >= 65536)
        {
            swWarn("Invalid port argument[%d]", _port);
            return false;
        }
    }

    host = _host;
    port = _port;

    struct sockaddr *_target_addr = nullptr;

    for (int i = 0; i < 2; i++)
    {
        if (sock_domain == AF_INET)
        {
            socket->info.addr.inet_v4.sin_family = AF_INET;
            socket->info.addr.inet_v4.sin_port = htons(_port);

            if (!inet_pton(AF_INET, host.c_str(), & socket->info.addr.inet_v4.sin_addr))
            {
                host = Coroutine::gethostbyname(host, AF_INET);
                if (host.empty())
                {
                    set_err(SwooleG.error);
                    return false;
                }
                continue;
            }
            else
            {
                socket->info.len = sizeof(socket->info.addr.inet_v4);
                _target_addr = (struct sockaddr *) &socket->info.addr.inet_v4;
                break;
            }
        }
        else if (sock_domain == AF_INET6)
        {
            socket->info.addr.inet_v6.sin6_family = AF_INET6;
            socket->info.addr.inet_v6.sin6_port = htons(_port);

            if (!inet_pton(AF_INET6, host.c_str(), &socket->info.addr.inet_v6.sin6_addr))
            {
                host = Coroutine::gethostbyname(host, AF_INET6);
                if (host.empty())
                {
                    set_err(SwooleG.error);
                    return false;
                }
                continue;
            }
            else
            {
                socket->info.len = sizeof(socket->info.addr.inet_v6);
                _target_addr = (struct sockaddr *) &socket->info.addr.inet_v6;
                break;
            }
        }
        else if (sock_domain == AF_UNIX)
        {
            if (host.size() >= sizeof(socket->info.addr.un.sun_path))
            {
                return false;
            }
            socket->info.addr.un.sun_family = AF_UNIX;
            memcpy(&socket->info.addr.un.sun_path, host.c_str(), host.size());
            socket->info.len = (socklen_t) (offsetof(struct sockaddr_un, sun_path) + host.size());
            _target_addr = (struct sockaddr *) &socket->info.addr.un;
            break;
        }
        else
        {
            return false;
        }
    }
    if (connect(_target_addr, socket->info.len) == false)
    {
        return false;
    }
    //socks5 proxy
    if (socks5_proxy && socks5_handshake() == false)
    {
        return false;
    }
    //http proxy
    if (http_proxy && http_proxy_handshake() == false)
    {
        return false;
    }
#ifdef SW_USE_OPENSSL
    if (open_ssl && ssl_handshake() == false)
    {
        return false;
    }
#endif
    return true;
}

bool Socket::is_connect()
{
    return socket->active && !socket->closed;
}

bool Socket::check_liveness()
{
    if (!is_connect())
    {
        set_err(ECONNRESET);
        return false;
    }
    else
    {
        static char buf;
        errno = 0;
        int ret = swConnection_peek(socket, &buf, sizeof(buf), 0);
        if (ret == 0 || (ret < 0 && swConnection_error(errno) != SW_WAIT)) {
            set_err(errno ? errno : ECONNRESET);
            return false;
        }
    }
    set_err(0);
    return true;
}

ssize_t Socket::peek(void *__buf, size_t __n)
{
    ssize_t retval = swConnection_peek(socket, __buf, __n, 0);
    set_err(retval < 0 ? errno : 0);
    return retval;
}

ssize_t Socket::recv(void *__buf, size_t __n)
{
    if (unlikely(!is_available()))
    {
        return -1;
    }
    ssize_t retval = swConnection_recv(socket, __buf, __n, 0);
    while (retval < 0 && swConnection_error(errno) == SW_WAIT)
    {
        if (!wait_readable())
        {
            return -1;
        }
        retval = swConnection_recv(socket, __buf, __n, 0);
    }
    set_err(retval < 0 ? errno : 0);
    return retval;
}

ssize_t Socket::read(void *__buf, size_t __n)
{
    if (unlikely(!is_available()))
    {
        return -1;
    }
    ssize_t retval = ::read(socket->fd, __buf, __n);
    while (retval < 0 && swConnection_error(errno) == SW_WAIT)
    {
        if (!wait_readable())
        {
            return -1;
        }
        retval = ::read(socket->fd, __buf, __n);
    }
    set_err(retval < 0 ? errno : 0);
    return retval;
}

ssize_t Socket::write(const void *__buf, size_t __n)
{
    if (unlikely(!is_available()))
    {
        return -1;
    }
    ssize_t retval = ::write(socket->fd, (void *) __buf, __n);
    while (retval < 0 && swConnection_error(errno) == SW_WAIT)
    {
        if (!wait_writeable(&__buf, __n))
        {
            return -1;
        }
        retval = ::write(socket->fd, (void *) __buf, __n);
    }
    set_err(retval < 0 ? errno : 0);
    return retval;
}

ssize_t Socket::recv_all(void *__buf, size_t __n)
{
    ssize_t retval, total_bytes = 0;
    if (unlikely(!is_available()))
    {
        return -1;
    }
    set_timer(TIMER_LV_MULTI);
    while (true)
    {
        retval = recv((char*) __buf + total_bytes, __n - total_bytes);
        if (retval <= 0)
        {
            if (total_bytes == 0)
            {
                total_bytes = retval;
            }
            break;
        }
        total_bytes += retval;
        if ((size_t) total_bytes == __n)
        {
            break;
        }
    }
    del_timer(TIMER_LV_MULTI);
    return total_bytes;
}

ssize_t Socket::send_all(const void *__buf, size_t __n)
{
    ssize_t retval, total_bytes = 0;
    if (unlikely(!is_available()))
    {
        return -1;
    }
    set_timer(TIMER_LV_MULTI);
    while (true)
    {
        retval = send((char*) __buf + total_bytes, __n - total_bytes);
        if (retval <= 0)
        {
            if (total_bytes == 0)
            {
                total_bytes = retval;
            }
            break;
        }
        total_bytes += retval;
        if ((size_t) total_bytes == __n)
        {
            break;
        }
    }
    del_timer(TIMER_LV_MULTI);
    return total_bytes;
}

ssize_t Socket::send(const void *__buf, size_t __n)
{
    if (unlikely(!is_available()))
    {
        return -1;
    }
    ssize_t retval = swConnection_send(socket, (void *) __buf, __n, 0);
    while (retval < 0 && swConnection_error(errno) == SW_WAIT)
    {
        if (!wait_writeable(&__buf, __n))
        {
            return -1;
        }
        retval = swConnection_send(socket, (void *) __buf, __n, 0);
    }
    set_err(retval < 0 ? errno : 0);
    return retval;
}

/**
 * Notice: you must use non-global buffer here (or else it may be changed after yield)
 */
ssize_t Socket::sendmsg(const struct msghdr *msg, int flags)
{
    if (unlikely(!is_available()))
    {
        return -1;
    }
    ssize_t retval = ::sendmsg(socket->fd, msg, flags);
    while (retval < 0 && swConnection_error(errno) == SW_WAIT)
    {
        if (!wait_writeable())
        {
            return -1;
        }
        retval = ::sendmsg(socket->fd, msg, flags);
    }
    set_err(retval < 0 ? errno : 0);
    return retval;
}

ssize_t Socket::recvmsg(struct msghdr *msg, int flags)
{
    if (unlikely(!is_available()))
    {
        return -1;
    }
    ssize_t retval = ::recvmsg(socket->fd, msg, flags);
    while (retval < 0 && swConnection_error(errno) == SW_WAIT)
    {
        if (!wait_readable())
        {
            return -1;
        }
        retval = ::recvmsg(socket->fd, msg, flags);
    }
    set_err(retval < 0 ? errno : 0);
    return retval;
}

bool Socket::bind(std::string address, int port)
{
    if (unlikely(!is_available()))
    {
        return false;
    }

    bind_address = address;
    bind_port = port;

    struct sockaddr *sock_type = (struct sockaddr*) &bind_address_info.addr.un;

    int option = 1;
    if (::setsockopt(socket->fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int)) < 0)
    {
        swSysError("setsockopt(%d, SO_REUSEADDR) failed.", socket->fd);
    }
#ifdef HAVE_REUSEPORT
    if (SwooleG.reuse_port)
    {
        if (::setsockopt(socket->fd, SOL_SOCKET, SO_REUSEPORT, &option, sizeof(int)) < 0)
        {
            swSysError("setsockopt(SO_REUSEPORT) failed.");
            SwooleG.reuse_port = 0;
        }
    }
#endif

    int retval;
    switch (sock_domain)
    {
    case AF_UNIX:
    {
        struct sockaddr_un *sa = (struct sockaddr_un *) sock_type;
        sa->sun_family = AF_UNIX;

        if (bind_address.size() >= sizeof(sa->sun_path))
        {
            return false;
        }
        memcpy(&sa->sun_path, bind_address.c_str(), bind_address.size());

        retval = ::bind(socket->fd, (struct sockaddr *) sa,
        offsetof(struct sockaddr_un, sun_path) + bind_address.size());
        break;
    }

    case AF_INET:
    {
        struct sockaddr_in *sa = (struct sockaddr_in *) sock_type;
        sa->sin_family = AF_INET;
        sa->sin_port = htons((unsigned short) bind_port);
        if (!inet_aton(bind_address.c_str(), &sa->sin_addr))
        {
            return false;
        }
        retval = ::bind(socket->fd, (struct sockaddr *) sa, sizeof(struct sockaddr_in));
        break;
    }

    case AF_INET6:
    {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *) sock_type;
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons((unsigned short) bind_port);

        if (!inet_pton(AF_INET6, bind_address.c_str(), &sa->sin6_addr))
        {
            return false;
        }
        retval = ::bind(socket->fd, (struct sockaddr *) sa, sizeof(struct sockaddr_in6));
        break;
    }
    default:
        set_err(EINVAL);
        return false;
    }

    if (retval != 0)
    {
        set_err(errno);
        return false;
    }

    return true;
}

bool Socket::listen(int backlog)
{
    if (unlikely(!is_available()))
    {
        return false;
    }
    this->backlog = backlog <= 0 ? SW_BACKLOG : backlog;
    if (::listen(socket->fd, this->backlog) != 0)
    {
        set_err(errno);
        return false;
    }
#ifdef SW_USE_OPENSSL
    if (open_ssl)
    {
        ssl_context = swSSL_get_context(&ssl_option);
        if (ssl_context == nullptr)
        {
            swWarn("swSSL_get_context() error.");
            return false;
        }
    }
#endif
    return true;
}

Socket* Socket::accept()
{
    if (unlikely(!is_available()))
    {
        return nullptr;
    }
    swSocketAddress client_addr;
    int conn = swSocket_accept(socket->fd, &client_addr);
    if (conn < 0 && errno == EAGAIN)
    {
        if (!wait_readable())
        {
            return nullptr;
        }
        conn = swSocket_accept(socket->fd, &client_addr);
    }
    if (conn < 0)
    {
        set_err(errno);
        return nullptr;
    }
    Socket *client_sock = new Socket(conn, this);
    if (unlikely(client_sock->socket == nullptr))
    {
        swWarn("new Socket() failed. Error: %s [%d]", strerror(errno), errno);
        set_err(errno);
        delete client_sock;
        return nullptr;
    }
    memcpy(&client_sock->socket->info.addr, &client_addr.addr, client_addr.len);
#ifdef SW_USE_OPENSSL
    if (open_ssl)
    {
        if (swSSL_create(client_sock->socket, ssl_context, 0) < 0)
        {
            _delete: delete client_sock;
            return nullptr;
        }
        if (client_sock->ssl_accept() == false)
        {
            goto _delete;
        }
    }
#endif
    return client_sock;
}

bool Socket::shutdown(int __how)
{
    if (__how == SHUT_RD && !shutdown_read)
    {
        if (::shutdown(socket->fd, SHUT_RD) == 0)
        {
            shutdown_read = true;
            return true;
        }
    }
    else if (__how == SHUT_WR && !shutdown_write)
    {
        if (::shutdown(socket->fd, SHUT_WR) == 0)
        {
            shutdown_write = true;
            return true;
        }
    }
    else if (__how == SHUT_RDWR && !shutdown_read && !shutdown_write)
    {
        if (::shutdown(socket->fd, SHUT_RDWR) == 0)
        {
            shutdown_read = shutdown_write = true;
            return true;
        }
    }
    set_err(errno);
    return false;
}

bool Socket::close()
{
    // TODO: waiting on review
    if (!socket->closed)
    {
        socket->closed = 1;
    }
    if (socket->active)
    {
        shutdown();
        socket->active = 0;
    }
    if (coroutine)
    {
        reactor->del(reactor, socket->fd);
        resume();
    }
    return true;
}

#ifdef SW_USE_OPENSSL
bool Socket::ssl_handshake()
{
    if (unlikely(!is_available()))
    {
        return -1;
    }
    if (socket->ssl)
    {
        return false;
    }
    ssl_context = swSSL_get_context(&ssl_option);
    if (ssl_context == NULL)
    {
        return false;
    }

    if (ssl_option.verify_peer)
    {
        if (swSSL_set_capath(&ssl_option, ssl_context) < 0)
        {
            return false;
        }
    }

    socket->ssl_send = 1;
#if defined(SW_USE_HTTP2) && defined(SW_USE_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (http2)
    {
        if (SSL_CTX_set_alpn_protos(ssl_context, (const unsigned char *) "\x02h2", 3) < 0)
        {
            return false;
        }
    }
#endif

    if (swSSL_create(socket, ssl_context, SW_SSL_CLIENT) < 0)
    {
        return false;
    }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (ssl_option.tls_host_name)
    {
        SSL_set_tlsext_host_name(socket->ssl, ssl_option.tls_host_name);
    }
#endif

    while (true)
    {
        int retval = swSSL_connect(socket);
        if (retval < 0)
        {
            set_err(SwooleG.error);
            return false;
        }
        if (socket->ssl_state == SW_SSL_STATE_WAIT_STREAM)
        {
            if (!wait_readable())
            {
                return false;
            }
        }
        else if (socket->ssl_state == SW_SSL_STATE_READY)
        {
            return true;
        }
    }

    if (socket->ssl_state == SW_SSL_STATE_READY && ssl_option.verify_peer)
    {
        if (ssl_verify(ssl_option.allow_self_signed) < 0)
        {
            return false;
        }
    }
    return true;
}

bool Socket::ssl_accept()
{
    open_ssl = true;
    while (true)
    {
        int retval = swSSL_accept(socket);
        if (retval == SW_ERROR)
        {
            return false;
        }
        else if (retval == SW_READY)
        {
            return true;
        }
        if (!wait_readable())
        {
            return -1;
        }
    }
}

int Socket::ssl_verify(bool allow_self_signed)
{
    if (unlikely(!is_available()))
    {
        return -1;
    }
    if (swSSL_verify(socket, allow_self_signed) < 0)
    {
        return SW_ERR;
    }
    if (ssl_option.tls_host_name && swSSL_check_host(socket, ssl_option.tls_host_name) < 0)
    {
        return SW_ERR;
    }
    return SW_OK;
}
#endif

bool Socket::sendfile(char *filename, off_t offset, size_t length)
{
    if (unlikely(!is_available()))
    {
        return false;
    }
    int file_fd = open(filename, O_RDONLY);
    if (file_fd < 0)
    {
        swSysError("open(%s) failed.", filename);
        return false;
    }

    if (length == 0)
    {
        struct stat file_stat;
        if (::fstat(file_fd, &file_stat) < 0)
        {
            swSysError("fstat(%s) failed.", filename);
            ::close(file_fd);
            return false;
        }
        length = file_stat.st_size;
    }
    else
    {
        // total length of the file
        length = offset + length;
    }

    int n, sendn;
    set_timer(TIMER_LV_MULTI);
    while ((size_t) offset < length)
    {
        sendn = (length - offset > SW_SENDFILE_CHUNK_SIZE) ? SW_SENDFILE_CHUNK_SIZE : length - offset;
#ifdef SW_USE_OPENSSL
        if (socket->ssl)
        {
            n = swSSL_sendfile(socket, file_fd, &offset, sendn);
        }
        else
#endif
        {
            n = ::swoole_sendfile(socket->fd, file_fd, &offset, sendn);
        }
        if (n > 0)
        {
            continue;
        }
        else if (n == 0)
        {
            swWarn("sendfile return zero.");
            ::close(file_fd);
            return false;
        }
        else if (errno != EAGAIN)
        {
            swSysError("sendfile(%d, %s) failed.", socket->fd, filename);
            set_err(errno);
            ::close(file_fd);
            return false;
        }
        if (!wait_writeable())
        {
            ::close(file_fd);
            return false;
        }
    }
    del_timer(TIMER_LV_MULTI);
    ::close(file_fd);
    return true;
}

ssize_t Socket::sendto(char *address, int port, char *data, int len)
{
    if (unlikely(!is_available()))
    {
        return -1;
    }
    if (type == SW_SOCK_UDP)
    {
        return swSocket_udp_sendto(socket->fd, address, port, data, len);
    }
    else if (type == SW_SOCK_UDP6)
    {
        return swSocket_udp_sendto6(socket->fd, address, port, data, len);
    }
    else
    {
        swWarn("only supports SWOOLE_SOCK_UDP or SWOOLE_SOCK_UDP6.");
        return -1;
    }
}

ssize_t Socket::recvfrom(void *__buf, size_t __n)
{
    if (unlikely(!is_available()))
    {
        return -1;
    }
    socket->info.len = sizeof(socket->info.addr);
    return recvfrom(__buf, __n, (struct sockaddr*) &socket->info.addr, &socket->info.len);
}

ssize_t Socket::recvfrom(void *__buf, size_t __n, struct sockaddr* _addr, socklen_t *_socklen)
{
    if (unlikely(!is_available()))
    {
        return -1;
    }
    ssize_t retval = ::recvfrom(socket->fd, __buf, __n, 0, _addr, _socklen);
    while (retval < 0 && errno == EINTR)
    {
        retval = ::recvfrom(socket->fd, __buf, __n, 0, _addr, _socklen);
    }
    while (retval < 0 && swConnection_error(errno) == SW_WAIT)
    {
        if (!wait_readable())
        {
            return -1;
        }
        retval = ::recvfrom(socket->fd, __buf, __n, 0, _addr, _socklen);
    }
    set_err(retval < 0 ? errno : 0);
    return retval;
}

/**
 * recv packet with protocol
 */
ssize_t Socket::recv_packet()
{
    if (unlikely(!is_available()))
    {
        return -1;
    }

    get_read_buffer();
    ssize_t buf_len = SW_BUFFER_SIZE_STD;
    ssize_t retval;

    if (open_length_check)
    {
        //unprocessed data
        if (read_buffer->offset > 0)
        {
            memmove(read_buffer->str, read_buffer->str + read_buffer->offset, read_buffer->length);
            read_buffer->offset = 0;
        }
        uint32_t header_len = protocol.package_length_offset + protocol.package_length_size;
        if (read_buffer->length > 0)
        {
            if (read_buffer->length < header_len)
            {
                goto _recv_header;
            }
            else
            {
                goto _get_length;
            }
        }

        _recv_header:
        retval = recv(read_buffer->str + read_buffer->length, header_len - read_buffer->length);
        if (retval <= 0)
        {
            return 0;
        }
        else
        {
            read_buffer->length += retval;
        }

        _get_length:
        buf_len = protocol.get_package_length(&protocol, socket, read_buffer->str, (uint32_t) read_buffer->length);
        swTraceLog(SW_TRACE_SOCKET, "packet_len=%ld, length=%ld", buf_len, read_buffer->length);
        //error package
        if (buf_len < 0)
        {
            return 0;
        }
        else if (buf_len == 0)
        {
            header_len = protocol.real_header_length;
            goto _recv_header;
        }
        //empty package
        else if (buf_len == header_len)
        {
            read_buffer->length = 0;
            return header_len;
        }
        else if (buf_len > protocol.package_max_length)
        {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_PACKAGE_LENGTH_TOO_LARGE, "packet[length=%d] is too big.", (int )buf_len);
            return 0;
        }

        if ((size_t) buf_len == read_buffer->length)
        {
            read_buffer->length = 0;
            return buf_len;
        }
        else if ((size_t) buf_len < read_buffer->length)
        {
            //unprocessed data
            read_buffer->length -= buf_len;
            read_buffer->offset = buf_len;
            return buf_len;
        }

        if ((size_t) buf_len > read_buffer->size)
        {
            if (swString_extend(read_buffer, buf_len) < 0)
            {
                read_buffer->length = 0;
                return -1;
            }
        }

        retval = recv_all(read_buffer->str + read_buffer->length, buf_len - read_buffer->length);
        if (retval > 0)
        {
            read_buffer->length += retval;
            if (read_buffer->length != (size_t) buf_len)
            {
                retval = 0;
            }
            else
            {
                read_buffer->length = 0;
                return buf_len;
            }
        }
    }
    else if (open_eof_check)
    {
        int eof = -1;
        char *buf;

        if (read_buffer->length > 0)
        {
            goto find_eof;
        }

        while (1)
        {
            buf = read_buffer->str + read_buffer->length;
            buf_len = read_buffer->size - read_buffer->length;

            if (buf_len > SW_BUFFER_SIZE_BIG)
            {
                buf_len = SW_BUFFER_SIZE_BIG;
            }

            retval = recv(buf, buf_len);
            if (retval < 0)
            {
                read_buffer->length = 0;
                return -1;
            }
            else if (retval == 0)
            {
                read_buffer->length = 0;
                return 0;
            }

            read_buffer->length += retval;

            if (read_buffer->length < protocol.package_eof_len)
            {
                continue;
            }

            find_eof: eof = swoole_strnpos(read_buffer->str, read_buffer->length, protocol.package_eof, protocol.package_eof_len);
            if (eof >= 0)
            {
                eof += protocol.package_eof_len;
                if (read_buffer->length > (uint32_t) eof)
                {
                    read_buffer->length -= eof;
                    memmove(read_buffer->str, read_buffer->str + eof, read_buffer->length);
                }
                else
                {
                    read_buffer->length = 0;
                }
                return eof;
            }
            else
            {
                if (read_buffer->length == protocol.package_max_length)
                {
                    swWarn("no package eof");
                    read_buffer->length = 0;
                    return -1;
                }
                else if (read_buffer->length == read_buffer->size)
                {
                    if (read_buffer->size < protocol.package_max_length)
                    {
                        size_t new_size = read_buffer->size * 2;
                        if (new_size > protocol.package_max_length)
                        {
                            new_size = protocol.package_max_length;
                        }
                        if (swString_extend(read_buffer, new_size) < 0)
                        {
                            read_buffer->length = 0;
                            return -1;
                        }
                    }
                }
            }
        }
        read_buffer->length = 0;
    }
    else
    {
        return -1;
    }

    return retval;
}

Socket::~Socket()
{
    int fd;
    if (socket == nullptr)
    {
        // construct failed
        return;
    }
    if (read_buffer)
    {
        swString_free(read_buffer);
    }
    if (write_buffer)
    {
        swString_free(write_buffer);
    }
    if (sock_domain == AF_UNIX && !bind_address.empty())
    {
        unlink(bind_address_info.addr.un.sun_path);
    }
    if (sock_type == SW_SOCK_UNIX_DGRAM)
    {
        unlink(socket->info.addr.un.sun_path);
    }
#ifdef SW_USE_OPENSSL
    if (socket->ssl)
    {
        swSSL_close(socket);
    }
    if (ssl_context)
    {
        swSSL_free_context(ssl_context);
        if (ssl_option.cert_file)
        {
            sw_free(ssl_option.cert_file);
        }
        if (ssl_option.key_file)
        {
            sw_free(ssl_option.key_file);
        }
        if (ssl_option.passphrase)
        {
            sw_free(ssl_option.passphrase);
        }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        if (ssl_option.tls_host_name)
        {
            sw_free(ssl_option.tls_host_name);
        }
#endif
        if (ssl_option.cafile)
        {
            sw_free(ssl_option.cafile);
        }
        if (ssl_option.capath)
        {
            sw_free(ssl_option.capath);
        }
    }
#endif
    if (socket->in_buffer)
    {
        swBuffer_free(socket->in_buffer);
    }
    if (socket->out_buffer)
    {
        swBuffer_free(socket->out_buffer);
    }
    fd = socket->fd;
    if (socket->removed == 0)
    {
        reactor->del(reactor, fd);
    }
    bzero(socket, sizeof(swConnection));
    socket->removed = 1;
    socket->closed = 1;
    ::close(fd);
}
