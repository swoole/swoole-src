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

#include "swoole.h"

#include <sys/stat.h>
#include <sys/poll.h>

int swSocket_sendfile_sync(int sock, char *filename, double timeout)
{
    int timeout_ms = timeout < 0 ? -1 : timeout * 1000;
    int file_fd = open(filename, O_RDONLY);
    if (file_fd < 0)
    {
        swWarn("open(%s) failed. Error: %s[%d]", filename, strerror(errno), errno);
        return SW_ERR;
    }

    struct stat file_stat;
    if (fstat(file_fd, &file_stat) < 0)
    {
        swWarn("fstat() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }

    int n, sendn;
    off_t offset = 0;
    size_t file_size = file_stat.st_size;

    while (offset < file_size)
    {
        if (swSocket_wait(sock, timeout_ms, SW_EVENT_WRITE) < 0)
        {
            return SW_ERR;
        }
        else
        {
            sendn = (file_size - offset > SW_SENDFILE_TRUNK) ? SW_SENDFILE_TRUNK : file_size - offset;
            n = swoole_sendfile(sock, file_fd, &offset, sendn);
            if (n <= 0)
            {
                swWarn("sendfile() failed. Error: %s[%d]", strerror(errno), errno);
                return SW_ERR;
            }
            else
            {
                continue;
            }
        }
    }
    return SW_OK;
}

/**
 * clear socket buffer.
 */
void swSocket_clean(int fd, void *buf, int len)
{
    while (recv(fd, buf, len, MSG_DONTWAIT) > 0)
        ;
}

/**
 * Wait socket can read or write.
 */
int swSocket_wait(int fd, int timeout_ms, int events)
{
    struct pollfd event;
    event.fd = fd;
    event.events = 0;

    if (events & SW_EVENT_READ)
    {
        event.events |= POLLIN;
    }
    if (events & SW_EVENT_WRITE)
    {
        event.events |= POLLOUT;
    }
    while (1)
    {
        int ret = poll(&event, 1, timeout_ms);
        if (ret == 0)
        {
            return SW_ERR;
        }
        else if (ret < 0 && errno != EINTR)
        {
            swWarn("poll() failed. Error: %s[%d]", strerror(errno), errno);
            return SW_ERR;
        }
        else
        {
            return SW_OK;
        }
    }
    return SW_OK;
}

int swSocket_write_blocking(int __fd, void *__data, int __len)
{
    int n = 0;
    int written = 0;

    while (written < __len)
    {
        n = write(__fd, __data + written, __len - written);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else if (errno == EAGAIN)
            {
                swSocket_wait(__fd, SW_WORKER_WAIT_TIMEOUT, SW_EVENT_WRITE);
                continue;
            }
            else
            {
                swSysError("write %d bytes failed.", __len);
                return SW_ERR;
            }
        }
        written += n;
    }

    return written;
}

int swSocket_sendto_blocking(int fd, void *__buf, size_t __n, int flag, struct sockaddr *__addr, socklen_t __addr_len)
{
    int n = 0;

    while (1)
    {
        n = sendto(fd, __buf, __n, flag, __addr, __addr_len);
        if (n >= 0)
        {
            break;
        }
        else
        {
            if (errno == EINTR)
            {
                continue;
            }
            else if (errno == EAGAIN)
            {
                swSocket_wait(fd, 1000, SW_EVENT_WRITE);
                continue;
            }
            else
            {
                break;
            }
        }
    }

    return n;
}

int swSocket_create(int type)
{
    int _domain;
    int _type;

    switch (type)
    {
    case SW_SOCK_TCP:
        _domain = PF_INET;
        _type = SOCK_STREAM;
        break;
    case SW_SOCK_TCP6:
        _domain = PF_INET6;
        _type = SOCK_STREAM;
        break;
    case SW_SOCK_UDP:
        _domain = PF_INET;
        _type = SOCK_DGRAM;
        break;
    case SW_SOCK_UDP6:
        _domain = PF_INET6;
        _type = SOCK_DGRAM;
        break;
    case SW_SOCK_UNIX_DGRAM:
        _domain = PF_UNIX;
        _type = SOCK_DGRAM;
        break;
    case SW_SOCK_UNIX_STREAM:
        _domain = PF_UNIX;
        _type = SOCK_STREAM;
        break;
    default:
        return SW_ERR;
    }
    return socket(_domain, _type, 0);
}

int swSocket_listen(int type, char *host, int port, int backlog)
{
    int sock;
    int option;
    int ret;

    struct sockaddr_in addr_in4;
    struct sockaddr_in6 addr_in6;
    struct sockaddr_un addr_un;

    sock = swSocket_create(type);
    if (sock < 0)
    {
        swWarn("create socket failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    //reuse
    option = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int));

    //unix socket
    if (type == SW_SOCK_UNIX_DGRAM || type == SW_SOCK_UNIX_STREAM)
    {
        bzero(&addr_un, sizeof(addr_un));
        unlink(host);
        addr_un.sun_family = AF_UNIX;
        strcpy(addr_un.sun_path, host);
        ret = bind(sock, (struct sockaddr*) &addr_un, sizeof(addr_un));
    }
    //IPv6
    else if (type > SW_SOCK_UDP)
    {
        bzero(&addr_in6, sizeof(addr_in6));
        inet_pton(AF_INET6, host, &(addr_in6.sin6_addr));
        addr_in6.sin6_port = htons(port);
        addr_in6.sin6_family = AF_INET6;
        ret = bind(sock, (struct sockaddr *) &addr_in6, sizeof(addr_in6));
    }
    //IPv4
    else
    {
        bzero(&addr_in4, sizeof(addr_in4));
        inet_pton(AF_INET, host, &(addr_in4.sin_addr));
        addr_in4.sin_port = htons(port);
        addr_in4.sin_family = AF_INET;
        ret = bind(sock, (struct sockaddr *) &addr_in4, sizeof(addr_in4));
    }
    //bind failed
    if (ret < 0)
    {
        swWarn("bind(%s:%d) failed. Error: %s [%d]", host, port, strerror(errno), errno);
        return SW_ERR;
    }
    if (type == SW_SOCK_UDP || type == SW_SOCK_UDP6 || type == SW_SOCK_UNIX_DGRAM)
    {
        return sock;
    }
    //listen stream socket
    ret = listen(sock, backlog);
    if (ret < 0)
    {
        swWarn("listen(%d) failed. Error: %s[%d]", backlog, strerror(errno), errno);
        return SW_ERR;
    }
    swSetNonBlock(sock);
    return sock;
}
