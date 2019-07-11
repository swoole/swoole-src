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
#include "connection.h"

int swSocket_sendfile_sync(int sock, const char *filename, off_t offset, size_t length, double timeout)
{
    int timeout_ms = timeout < 0 ? -1 : timeout * 1000;
    int file_fd = open(filename, O_RDONLY);
    if (file_fd < 0)
    {
        swSysWarn("open(%s) failed", filename);
        return SW_ERR;
    }

    if (length == 0)
    {
        struct stat file_stat;
        if (fstat(file_fd, &file_stat) < 0)
        {
            swSysWarn("fstat() failed");
            close(file_fd);
            return SW_ERR;
        }
        length = file_stat.st_size;
    }
    else
    {
        length = offset + length;
    }

    int n, sendn;
    while (offset < length)
    {
        if (swSocket_wait(sock, timeout_ms, SW_EVENT_WRITE) < 0)
        {
            close(file_fd);
            return SW_ERR;
        }
        else
        {
            sendn = (length - offset > SW_SENDFILE_CHUNK_SIZE) ? SW_SENDFILE_CHUNK_SIZE : length - offset;
            n = swoole_sendfile(sock, file_fd, &offset, sendn);
            if (n <= 0)
            {
                close(file_fd);
                swSysWarn("sendfile(%d, %s) failed", sock, filename);
                return SW_ERR;
            }
            else
            {
                continue;
            }
        }
    }
    close(file_fd);
    return SW_OK;
}

/**
 * clear socket buffer.
 */
void swSocket_clean(int fd)
{
    char buf[2048];
    while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0);
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
            swSysWarn("poll() failed");
            return SW_ERR;
        }
        else
        {
            return SW_OK;
        }
    }
    return SW_OK;
}

/**
 * Wait some sockets can read or write.
 */
int swSocket_wait_multi(int *list_of_fd, int n_fd, int timeout_ms, int events)
{
    assert(n_fd < 65535);

    struct pollfd *event_list = sw_calloc(n_fd, sizeof(struct pollfd));
    if (!event_list)
    {
        swWarn("malloc[1] failed");
        return SW_ERR;
    }
    int i;

    int _events = 0;
    if (events & SW_EVENT_READ)
    {
        _events |= POLLIN;
    }
    if (events & SW_EVENT_WRITE)
    {
        _events |= POLLOUT;
    }

    for (i = 0; i < n_fd; i++)
    {
        event_list[i].fd = list_of_fd[i];
        event_list[i].events = _events;
    }

    while (1)
    {
        int ret = poll(event_list, n_fd, timeout_ms);
        if (ret == 0)
        {
            sw_free(event_list);
            return SW_ERR;
        }
        else if (ret < 0 && errno != EINTR)
        {
            swSysWarn("poll() failed");
            sw_free(event_list);
            return SW_ERR;
        }
        else
        {
            sw_free(event_list);
            return ret;
        }
    }
    sw_free(event_list);
    return SW_OK;
}

int swSocket_write_blocking(int __fd, const void *__data, int __len)
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
            else if (swConnection_error(errno) == SW_WAIT)
            {
                swSocket_wait(__fd, SW_WORKER_WAIT_TIMEOUT, SW_EVENT_WRITE);
                continue;
            }
            else
            {
                swSysWarn("write %d bytes failed", __len);
                return SW_ERR;
            }
        }
        written += n;
    }

    return written;
}

int swSocket_recv_blocking(int fd, void *__data, size_t __len, int flags)
{
    int ret;
    size_t read_bytes = 0;

    while (read_bytes != __len)
    {
        errno = 0;
        ret = recv(fd, (char *) __data + read_bytes, __len - read_bytes, flags);
        if (ret > 0)
        {
            read_bytes += ret;
        }
        else if (ret == 0 && errno == 0)
        {
            return read_bytes;
        }
        else if (ret <= 0 && errno != 0 && errno != EINTR)
        {
            return ret;
        }
    }
    return read_bytes;
}

int swSocket_accept(int fd, swSocketAddress *sa)
{
    int conn;
    sa->len = sizeof(sa->addr);
#ifdef HAVE_ACCEPT4
    conn = accept4(fd, (struct sockaddr *) &sa->addr, &sa->len, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
    conn = accept(fd, (struct sockaddr *) &sa->addr, &sa->len);
    if (conn >= 0)
    {
        swoole_fcntl_set_option(conn, 1, 1);
    }
#endif
    return conn;
}

ssize_t swSocket_udp_sendto(int server_sock, const char *dst_ip, int dst_port, const char *data, uint32_t len)
{
    struct sockaddr_in addr;
    if (inet_aton(dst_ip, &addr.sin_addr) == 0)
    {
        swWarn("ip[%s] is invalid", dst_ip);
        return SW_ERR;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(dst_port);
    return swSocket_sendto_blocking(server_sock, data, len, 0, (struct sockaddr *) &addr, sizeof(addr));
}

ssize_t swSocket_udp_sendto6(int server_sock, const char *dst_ip, int dst_port, const char *data, uint32_t len)
{
    struct sockaddr_in6 addr;
    bzero(&addr, sizeof(addr));
    if (inet_pton(AF_INET6, dst_ip, &addr.sin6_addr) < 0)
    {
        swWarn("ip[%s] is invalid", dst_ip);
        return SW_ERR;
    }
    addr.sin6_port = (uint16_t) htons(dst_port);
    addr.sin6_family = AF_INET6;
    return swSocket_sendto_blocking(server_sock, data, len, 0, (struct sockaddr *) &addr, sizeof(addr));
}

ssize_t swSocket_unix_sendto(int server_sock, const char *dst_path, const char *data, uint32_t len)
{
    struct sockaddr_un addr;
    bzero(&addr, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, dst_path, sizeof(addr.sun_path) - 1);
    return swSocket_sendto_blocking(server_sock, data, len, 0, (struct sockaddr *) &addr, sizeof(addr));
}

ssize_t swSocket_sendto_blocking(int fd, const void *__buf, size_t __n, int flag, struct sockaddr *__addr, socklen_t __addr_len)
{
    ssize_t n = 0;

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
            else if (swConnection_error(errno) == SW_WAIT)
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
        swWarn("unknown socket type [%d]", type);
        return SW_ERR;
    }
    return socket(_domain, _type, 0);
}

int swSocket_bind(int sock, int type, const char *host, int *port)
{
    int ret;

    struct sockaddr_in addr_in4;
    struct sockaddr_in6 addr_in6;
    struct sockaddr_un addr_un;
    socklen_t len;

    //SO_REUSEADDR option
    int option = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int)) != 0)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SYSTEM_CALL_FAIL, "setsockopt(%d, SO_REUSEADDR) failed", sock);
    }
    //reuse port
#ifdef HAVE_REUSEPORT
    if (SwooleG.reuse_port)
    {
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &option, sizeof(int)) != 0)
        {
            swSysWarn("setsockopt(SO_REUSEPORT) failed");
            SwooleG.reuse_port = 0;
        }
    }
#endif

    //unix socket
    if (type == SW_SOCK_UNIX_DGRAM || type == SW_SOCK_UNIX_STREAM)
    {
        bzero(&addr_un, sizeof(addr_un));
        unlink(host);
        addr_un.sun_family = AF_UNIX;
        strncpy(addr_un.sun_path, host, sizeof(addr_un.sun_path) - 1);
        ret = bind(sock, (struct sockaddr*) &addr_un, sizeof(addr_un));
    }
    //IPv6
    else if (type > SW_SOCK_UDP)
    {
        bzero(&addr_in6, sizeof(addr_in6));
        if (inet_pton(AF_INET6, host, &(addr_in6.sin6_addr)) < 0)
        {
            swSysWarn("inet_pton(AF_INET6, %s) failed", host);
            return SW_ERR;
        }
        addr_in6.sin6_port = htons(*port);
        addr_in6.sin6_family = AF_INET6;
        ret = bind(sock, (struct sockaddr *) &addr_in6, sizeof(addr_in6));
        if (ret == 0 && *port == 0)
        {
            len = sizeof(addr_in6);
            if (getsockname(sock, (struct sockaddr *) &addr_in6, &len) != -1)
            {
                *port = ntohs(addr_in6.sin6_port);
            }
        }
    }
    //IPv4
    else
    {
        bzero(&addr_in4, sizeof(addr_in4));
        if (inet_pton(AF_INET, host, &(addr_in4.sin_addr)) < 0)
        {
            swSysWarn("inet_pton(AF_INET, %s) failed", host);
            return SW_ERR;
        }
        addr_in4.sin_port = htons(*port);
        addr_in4.sin_family = AF_INET;
        ret = bind(sock, (struct sockaddr *) &addr_in4, sizeof(addr_in4));
        if (ret == 0 && *port == 0)
        {
            len = sizeof(addr_in4);
            if (getsockname(sock, (struct sockaddr *) &addr_in4, &len) != -1)
            {
                *port = ntohs(addr_in4.sin_port);
            }
        }
    }
    //bind failed
    if (ret < 0)
    {
        swSysWarn("bind(%s:%d) failed", host, *port);
        return SW_ERR;
    }

    return ret;
}

int swSocket_set_buffer_size(int fd, uint32_t buffer_size)
{
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)) != 0)
    {
        swSysWarn("setsockopt(%d, SOL_SOCKET, SO_SNDBUF, %d) failed", fd, buffer_size);
        return SW_ERR;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size)) != 0)
    {
        swSysWarn("setsockopt(%d, SOL_SOCKET, SO_RCVBUF, %d) failed", fd, buffer_size);
        return SW_ERR;
    }
    return SW_OK;
}

int swSocket_set_timeout(int sock, double timeout)
{
    int ret;
    struct timeval timeo;
    timeo.tv_sec = (int) timeout;
    timeo.tv_usec = (int) ((timeout - timeo.tv_sec) * 1000 * 1000);
    ret = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (void *) &timeo, sizeof(timeo));
    if (ret < 0)
    {
        swSysWarn("setsockopt(SO_SNDTIMEO) failed");
        return SW_ERR;
    }
    ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &timeo, sizeof(timeo));
    if (ret < 0)
    {
        swSysWarn("setsockopt(SO_RCVTIMEO) failed");
        return SW_ERR;
    }
    return SW_OK;
}

int swSocket_create_server(int type, const char *address, int port, int backlog)
{
#if 0
    int type;
    char host[32];
    int port = 0;

    if (strncasecmp(address, "unix:/", 6) == 0)
    {
        address += 5;
        type = SW_SOCK_UNIX_STREAM;
    }
    else
    {
        char *port_str = strchr(address, ':');
        if (!port_str)
        {
            swoole_error_log(SW_LOG_ERROR, SW_ERROR_INVALID_PARAMS, "invalid address[%s]", address);
            return SW_ERR;
        }
        type = SW_SOCK_TCP6;
        memcpy(host, address, port_str - address);
        host[port_str - address] = 0;
        port = atoi(port_str + 1);
        address = host;
    }
#endif

    int fd = swSocket_create(type);
    if (fd < 0)
    {
        swSysWarn("socket() failed");
        return SW_ERR;
    }

    if (swSocket_bind(fd, type, address, &port) < 0)
    {
        close(fd);
        return SW_ERR;
    }

    if (listen(fd, backlog) < 0)
    {
        swSysWarn("listen(%s:%d, %d) failed", address, port, backlog);
        close(fd);
        return SW_ERR;
    }

    return fd;
}
