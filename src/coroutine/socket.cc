#include "Socket.h"
#include "context.h"
#include "async.h"
#include "buffer.h"

#include <string>
#include <iostream>

using namespace swoole;
using namespace std;

static int socket_onRead(swReactor *reactor, swEvent *event);
static int socket_onWrite(swReactor *reactor, swEvent *event);
static void socket_onTimeout(swTimer *timer, swTimer_node *tnode);
static void socket_onResolveCompleted(swAio_event *event);

Socket::Socket(enum swSocket_type type)
{
    int _domain;
    int _type;

    switch (type)
    {
    case SW_SOCK_TCP6:
        _domain = AF_INET6;
        _type = SOCK_STREAM;
        break;
    case SW_SOCK_UNIX_STREAM:
        _domain = AF_UNIX;
        _type = SOCK_STREAM;
        break;
    case SW_SOCK_UDP:
        _domain = AF_INET;
        _type = SOCK_DGRAM;
        break;
    case SW_SOCK_UDP6:
        _domain = AF_INET6;
        _type = SOCK_DGRAM;
        break;
    case SW_SOCK_UNIX_DGRAM:
        _domain = AF_UNIX;
        _type = SOCK_DGRAM;
        break;
    case SW_SOCK_TCP:
    default:
        _domain = AF_INET;
        _type = SOCK_STREAM;
        break;
    }

#ifdef SOCK_CLOEXEC
    int sockfd = ::socket(_domain, _type | SOCK_CLOEXEC, 0);
#else
    int sockfd = ::socket(_domain, _type, 0);
#endif
    if (sockfd < 0)
    {
        swWarn("socket() failed. Error: %s[%d]", strerror(errno), errno);
        return;
    }

    if (swIsMaster() && SwooleTG.type == SW_THREAD_REACTOR)
    {
        reactor = SwooleTG.reactor;
    }
    else
    {
        reactor = SwooleG.main_reactor;
    }
    socket = swReactor_get(reactor, sockfd);

    bzero(socket, sizeof(swConnection));
    socket->fd = sockfd;
    socket->object = this;

    swSetNonBlock(socket->fd);
    if (!swReactor_handle_isset(reactor, SW_FD_CORO_SOCKET))
    {
        reactor->setHandle(reactor, SW_FD_CORO_SOCKET | SW_EVENT_READ, socket_onRead);
        reactor->setHandle(reactor, SW_FD_CORO_SOCKET | SW_EVENT_WRITE, socket_onWrite);
        reactor->setHandle(reactor, SW_FD_CORO_SOCKET | SW_EVENT_ERROR, socket_onRead);
    }

    _sock_domain = _domain;
    _sock_type = _type;
    _cid = 0;
    _timeout = 0;
    _port = 0;
    errCode = 0;
    errMsg = nullptr;
    fd = sockfd;
    timer = nullptr;
    bind_port = 0;
    _backlog = 0;
}

Socket::Socket(int _fd, Socket *sock)
{
    fd = _fd;
    reactor = sock->reactor;

    socket = swReactor_get(reactor, fd);
    bzero(socket, sizeof(swConnection));
    socket->fd = fd;
    socket->object = this;

    _sock_domain = sock->_sock_domain;
    _sock_type = sock->_sock_type;
    _cid = 0;
    _timeout = 0;
    _port = 0;
    errCode = 0;
    errMsg = nullptr;
    timer = nullptr;
    bind_port = 0;
    _backlog = 0;
}

bool Socket::connect(string host, int port, int flags)
{
    if (_sock_domain == AF_INET6 || _sock_domain == AF_INET)
    {
        if (port == -1)
        {
            swWarn("Socket of type AF_INET/AF_INET6 requires port argument");
            return false;
        }
        else if (port == 0 || port >= 65536)
        {
            swWarn("Invalid port argument[%d]", port);
            return false;
        }
    }

    if (unlikely(_cid && _cid != coroutine_get_cid()))
    {
        swWarn( "socket has already been bound to another coroutine.");
        return false;
    }

    swAio_event ev;
    int retval;
    bool _try_gethost = false;

    _host = host;
    _port = port;

    _connect: switch (_sock_domain)
    {
    case AF_INET:
    {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (!inet_pton(AF_INET, _host.c_str(), &addr.sin_addr))
        {
            _gethost: if (_try_gethost)
            {
                retval = -1;
                break;
            }

            bzero(&ev, sizeof(swAio_event));
            _try_gethost = true;
            ev.nbytes = _host.size() < SW_IP_MAX_LENGTH ? SW_IP_MAX_LENGTH : _host.size() + 1;
            ev.buf = sw_malloc(ev.nbytes);
            if (!ev.buf)
            {
                return false;
            }

            memcpy(ev.buf, _host.c_str(), _host.size());
            ((char *) ev.buf)[_host.size()] = 0;
            ev.flags = _sock_domain;
            ev.type = SW_AIO_GETHOSTBYNAME;
            ev.object = this;
            ev.callback = socket_onResolveCompleted;

            if (SwooleAIO.init == 0)
            {
                swAio_init();
            }

            if (swAio_dispatch(&ev) < 0)
            {
                sw_free(ev.buf);
                return false;
            }
            else
            {
                yield();
                if (errCode == SW_ERROR_DNSLOOKUP_RESOLVE_FAILED)
                {
                    errMsg = hstrerror(ev.error);
                    return false;
                }
                goto _connect;
            }
        }
        else
        {
            socklen_t len = sizeof(addr);
            while (1)
            {
                retval = ::connect(socket->fd, (struct sockaddr *) &addr, len);
                if (retval < 0)
                {
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    errCode = errno;
                }
                break;
            }
            break;
        }
    }
    case AF_INET6:
    {
        struct sockaddr_in6 addr;
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);

        if (!inet_pton(AF_INET6, _host.c_str(), &addr.sin6_addr))
        {
            goto _gethost;
        }
        else
        {
            socklen_t len = sizeof(addr);
            while (1)
            {
                retval = ::connect(socket->fd, (struct sockaddr *) &addr, len);
                if (retval < 0)
                {
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    errCode = errno;
                }
                break;
            }
            break;
        }
    }
    case AF_UNIX:
    {
        struct sockaddr_un s_un = { 0 };
        if (_host.size() >= sizeof(s_un.sun_path))
        {
            return false;
        }

        s_un.sun_family = AF_UNIX;
        memcpy(&s_un.sun_path, _host.c_str(), _host.size());
        while (1)
        {
            retval = ::connect(socket->fd, (struct sockaddr *) &s_un, (socklen_t) (offsetof(struct sockaddr_un, sun_path) + _host.size()));
            if (retval < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                errCode = errno;
            }
            break;
        }
        break;
    }

    default:
        return false;
    }

    if (retval == -1 && errno == EINPROGRESS)
    {
        if (reactor->add(reactor, socket->fd, SW_FD_CORO_SOCKET | SW_EVENT_WRITE) < 0)
        {
            return false;
        }
        if (_timeout > 0)
        {
            int ms = (int) (_timeout * 1000);
            timer = SwooleG.timer.add(&SwooleG.timer, ms, 0, this, socket_onTimeout);
        }
        yield();
        if (timer)
        {
            swTimer_del(&SwooleG.timer, timer);
            timer = nullptr;
        }
        //Connection has timed out
        if (errCode == ETIMEDOUT)
        {
            errMsg = strerror(errCode);
            return false;
        }
        socklen_t len = sizeof(errCode);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &errCode, &len) < 0 || errCode != 0)
        {
            errMsg = strerror(errCode);
            return false;
        }
        else
        {
            return true;
        }
    }
    else
    {
        return false;
    }

}

static void socket_onResolveCompleted(swAio_event *event)
{
    Socket *sock = (Socket *) event->object;
    if (event->error == 0)
    {
        sock->_host = string((const char *) event->buf);
        sw_free(event->buf);
    }
    else
    {
        sock->errCode = SW_ERROR_DNSLOOKUP_RESOLVE_FAILED;
    }
    sock->resume();
}

static void socket_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    Socket *sock = (Socket *) tnode->data;
    sock->timer = NULL;
    sock->errCode = ETIMEDOUT;
    sock->reactor->del(sock->reactor, sock->fd);
    sock->resume();
}

static int socket_onRead(swReactor *reactor, swEvent *event)
{
    Socket *sock = (Socket *) event->socket->object;
    reactor->del(reactor, sock->fd);
    sock->resume();
    return SW_OK;
}

static int socket_onWrite(swReactor *reactor, swEvent *event)
{
    Socket *sock = (Socket *) event->socket->object;
    reactor->del(reactor, sock->fd);
    sock->resume();
    return SW_OK;
}

ssize_t Socket::recv(void *__buf, size_t __n, int __flags)
{
    if (reactor->add(reactor, socket->fd, SW_FD_CORO_SOCKET | SW_EVENT_READ) < 0)
    {
        _error: errCode = errno;
        return -1;
    }
    errCode = 0;
    if (_timeout > 0)
    {
        int ms = (int) (_timeout * 1000);
        timer = SwooleG.timer.add(&SwooleG.timer, ms, 0, this, socket_onTimeout);
    }
    yield();
    ssize_t retval = ::recv(fd, __buf, __n, __flags);
    if (retval < 0)
    {
        goto _error;
    }
    else
    {
        return retval;
    }
}

ssize_t Socket::send(const void *__buf, size_t __n, int __flags)
{
    ssize_t n = ::send(fd, __buf, __n, __flags);
    if (n >= 0)
    {
        return n;
    }
    if (errno != EAGAIN)
    {
        return n;
    }
    if (reactor->add(reactor, socket->fd, SW_FD_CORO_SOCKET | SW_EVENT_WRITE) < 0)
    {
        _error: errCode = errno;
        return -1;
    }
    errCode = 0;
    if (_timeout > 0)
    {
        int ms = (int) (_timeout * 1000);
        timer = SwooleG.timer.add(&SwooleG.timer, ms, 0, this, socket_onTimeout);
    }
    yield();
    ssize_t retval = ::send(fd, __buf, __n, __flags);
    if (retval < 0)
    {
        goto _error;
    }
    else
    {
        return retval;
    }
}

void Socket::yield()
{
    _cid = coroutine_get_cid();
    coroutine_yield(coroutine_get_by_id(_cid));
}

void Socket::resume()
{
    coroutine_resume(coroutine_get_by_id(_cid));
}

bool Socket::bind(std::string address, int port)
{
    bind_address = address;
    bind_port = port;

    struct sockaddr_storage sa_storage = { 0 };
    struct sockaddr *sock_type = (struct sockaddr*) &sa_storage;

    int retval;
    switch (_sock_domain)
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

        retval = ::bind(fd, (struct sockaddr *) sa,
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
        retval = ::bind(fd, (struct sockaddr *) sa, sizeof(struct sockaddr_in));
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
        retval = ::bind(fd, (struct sockaddr *) sa, sizeof(struct sockaddr_in6));
        break;
    }
    default:
        return false;
    }

    if (retval != 0)
    {
        errCode = errno;
        return false;
    }

    return true;
}

bool Socket::listen(int backlog)
{
    _backlog = backlog;
    if (::listen(fd, backlog) != 0)
    {
        errCode = errno;
        return false;
    }
    return true;
}

Socket* Socket::accept()
{
    if (reactor->add(reactor, socket->fd, SW_FD_CORO_SOCKET | SW_EVENT_READ) < 0)
    {
        _error: errCode = errno;
        return nullptr;
    }
    yield();
    int conn;
    swSocketAddress client_addr;
    socklen_t client_addrlen = sizeof(client_addr);

#ifdef HAVE_ACCEPT4
    conn = ::accept4(fd, (struct sockaddr *) &client_addr, &client_addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
    conn = ::accept(fd, (struct sockaddr *) &client_addr, &client_addrlen);
    if (conn >= 0)
    {
        swoole_fcntl_set_option(conn, 1, 1);
    }
#endif
    if (conn >= 0)
    {
        return new Socket(conn, this);
    }
    else
    {
        errCode = errno;
        return nullptr;
    }
}

bool Socket::close()
{
    if (socket == NULL || socket->closed)
    {
        return false;
    }
    socket->closed = 1;

    int fd = socket->fd;
    assert(fd != 0);

    if (_sock_type == SW_SOCK_UNIX_DGRAM)
    {
        unlink(socket->info.addr.un.sun_path);
    }
    //remove from reactor
    if (!socket->removed && reactor)
    {
        reactor->del(reactor, fd);
    }
    if (timer)
    {
        swTimer_del(&SwooleG.timer, timer);
        timer = NULL;
    }
    socket->active = 0;
    ::close(fd);
    return true;
}
Socket::~Socket()
{
    assert(socket->fd != 0);
    if (!socket->closed)
    {
        close();
    }
    if (socket->out_buffer)
    {
        swBuffer_free(socket->out_buffer);
        socket->out_buffer = NULL;
    }
    if (socket->in_buffer)
    {
        swBuffer_free(socket->in_buffer);
        socket->in_buffer = NULL;
    }
    bzero(socket, sizeof(swConnection));
    socket->removed = 1;
}

