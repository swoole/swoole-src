#include "socket.h"

#include <string>
#include <iostream>

using namespace swoole;
using namespace std;

extern "C"
{

int swoole_coroutine_socket(int domain, int type, int protocol)
{
    enum swSocket_type sock_type;
    if (domain == AF_INET)
    {
        sock_type = type == SOCK_STREAM ? SW_SOCK_TCP : SW_SOCK_UDP;
    }
    else if (domain == AF_INET6)
    {
        sock_type = type == SOCK_STREAM ? SW_SOCK_TCP6 : SW_SOCK_UDP6;
    }
    else if (domain == AF_UNIX)
    {
        sock_type = type == SOCK_STREAM ? SW_SOCK_UNIX_STREAM : SW_SOCK_UNIX_DGRAM;
    }
    else
    {
        errno = EINVAL;
        return -1;
    }
    Socket *sock = new Socket(sock_type);
    return sock->socket->fd;
}

ssize_t swoole_coroutine_send(int sockfd, const void *buf, size_t len, int flags)
{
    swConnection *conn = swReactor_get(SwooleG.main_reactor, sockfd);
    if (conn == nullptr)
    {
        errno = EBADF;
        return -1;
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

ssize_t swoole_coroutine_recv(int sockfd, void *buf, size_t len, int flags)
{
    swConnection *conn = swReactor_get(SwooleG.main_reactor, sockfd);
    if (conn == nullptr)
    {
        errno = EBADF;
        return -1;
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
    if (SwooleG.main_reactor == nullptr)
    {
        return close(fd);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, fd);
    if (conn == nullptr)
    {
        return close(fd);
    }
    else
    {
        delete (Socket *) conn->object;
        return 0;
    }
}

int swoole_coroutine_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    swConnection *conn = swReactor_get(SwooleG.main_reactor, sockfd);
    if (conn == nullptr)
    {
        errno = EBADF;
        return -1;
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

}

