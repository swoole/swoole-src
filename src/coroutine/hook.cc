#include "socket.h"
#include "coroutine.h"

#include <sys/poll.h>
#include <string>
#include <iostream>

using namespace swoole;
using namespace std;

extern "C"
{

int swoole_coroutine_socket(int domain, int type, int protocol)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        return socket(domain, type, protocol);
    }
    enum swSocket_type sock_type = get_socket_type(domain, type, protocol);
    Socket *sock = new Socket(sock_type);
    return sock->socket->fd;
}

ssize_t swoole_coroutine_send(int sockfd, const void *buf, size_t len, int flags)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        _no_coro: return ::send(sockfd, buf, len, flags);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, sockfd);
    if (conn == nullptr)
    {
        goto _no_coro;
    }
    Socket *socket = (Socket *) conn->object;
    ssize_t retval = socket->send(buf, len);
    if (retval < 0)
    {
        errno = socket->errCode;
        return -1;
    }
    else
    {
        errno = 0;
        return retval;
    }
}

ssize_t swoole_coroutine_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        _no_coro: return ::sendmsg(sockfd, msg, flags);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, sockfd);
    if (conn == nullptr)
    {
        goto _no_coro;
    }
    Socket *socket = (Socket *) conn->object;
    ssize_t retval = socket->sendmsg(msg, flags);
    if (retval < 0)
    {
        errno = socket->errCode;
        return -1;
    }
    else
    {
        errno = 0;
        return retval;
    }
}

ssize_t swoole_coroutine_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        _no_coro: return ::recvmsg(sockfd, msg, flags);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, sockfd);
    if (conn == nullptr)
    {
        goto _no_coro;
    }
    Socket *socket = (Socket *) conn->object;
    ssize_t retval = socket->recvmsg(msg, flags);
    if (retval < 0)
    {
        errno = socket->errCode;
        return -1;
    }
    else
    {
        errno = 0;
        return retval;
    }
}

ssize_t swoole_coroutine_recv(int sockfd, void *buf, size_t len, int flags)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        _no_coro: return ::recv(sockfd, buf, len, flags);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, sockfd);
    if (conn == nullptr)
    {
        goto _no_coro;
    }
    Socket *socket = (Socket *) conn->object;
    ssize_t retval = socket->recv(buf, len);
    if (retval < 0)
    {
        errno = socket->errCode;
        return -1;
    }
    else
    {
        errno = 0;
        return retval;
    }
}

int swoole_coroutine_close(int fd)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        _no_coro: return close(fd);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, fd);
    if (conn == nullptr)
    {
        goto _no_coro;
    }
    else
    {
        delete (Socket *) conn->object;
        return 0;
    }
}

int swoole_coroutine_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        _no_coro: return connect(sockfd, addr, addrlen);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, sockfd);
    if (conn == nullptr)
    {
        goto _no_coro;
    }
    Socket *socket = (Socket *) conn->object;
    if (socket->connect(addr, addrlen) == false)
    {
        errno = socket->errCode;
        return -1;
    }
    else
    {
        errno = 0;
        return 0;
    }
}

int swoole_coroutine_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1 || nfds != 1)
    {
        _poll: return poll(fds, nfds, timeout);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, fds[0].fd);
    if (conn == nullptr)
    {
        goto _poll;
    }
    Socket *socket = (Socket *) conn->object;
    socket->setTimeout((double) timeout / 1000);
    if (fds[0].events & POLLIN)
    {
        fds[0].revents |= POLLIN;
    }
    if (fds[0].events & POLLOUT)
    {
        fds[0].revents |= POLLOUT;
    }
    return 1;
}

}

