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

#include "swoole_api.h"
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
    while (offset < (off_t) length)
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

    if (timeout_ms < 0)
    {
        timeout_ms = -1;
    }

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

    struct pollfd *event_list = (struct pollfd *) sw_calloc(n_fd, sizeof(*event_list));
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

ssize_t swSocket_write_blocking(swSocket *sock, const void *__data, size_t __len)
{
    ssize_t n = 0;
    ssize_t written = 0;

    while (written < (ssize_t) __len)
    {
        n = write(sock->fd, (char *) __data + written, __len - written);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else if (swConnection_error(errno) == SW_WAIT
                    && swSocket_wait(sock->fd, (int) (SwooleG.socket_send_timeout * 1000), SW_EVENT_WRITE) == SW_OK)
            {
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

ssize_t swSocket_recv_blocking(swSocket *sock, void *__data, size_t __len, int flags)
{
    ssize_t ret;
    size_t read_bytes = 0;

    while (read_bytes != __len)
    {
        errno = 0;
        ret = recv(sock->fd, (char *) __data + read_bytes, __len - read_bytes, flags);
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

swSocket* swSocket_accept(swSocket *server_socket, swSocketAddress *sa)
{
    int conn;
    sa->len = sizeof(sa->addr);
#ifdef HAVE_ACCEPT4
    int flags = SOCK_CLOEXEC;
    if (server_socket->nonblock)
    {
        flags |= SOCK_NONBLOCK;
    }
    conn = accept4(server_socket->fd, (struct sockaddr *) &sa->addr, &sa->len, flags);
#else
    conn = accept(server_socket->fd, (struct sockaddr *) &sa->addr, &sa->len);
    if (conn >= 0)
    {
        swoole_fcntl_set_option(conn, server_socket->nonblock, 1);
    }
#endif

    if (conn < 0)
    {
        return nullptr;
    }

    swSocket *socket = swSocket_new(conn, SW_FD_SESSION);
    if (!socket)
    {
        close(conn);
    }
    else
    {
        socket->socket_type = server_socket->socket_type;
        socket->nonblock = server_socket->nonblock;
        socket->cloexec = 1;
        memcpy(&socket->info.addr, sa, sa->len);
        socket->info.len = sa->len;
    }

    return socket;
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

    for (int i = 0; i < SW_SOCKET_SYNC_SEND_RETRY_COUNT; i++)
    {
        n = sendto(fd, __buf, __n, flag, __addr, __addr_len);
        if (n >= 0)
        {
            break;
        }
        if (errno == EINTR)
        {
            continue;
        }
        if (swConnection_error(errno) == SW_WAIT
                && swSocket_wait(fd, (int) (SwooleG.socket_send_timeout * 1000), SW_EVENT_WRITE) == SW_OK)
        {
            continue;
        }
        break;
    }

    return n;
}

int swSocket_create(enum swSocket_type type, uchar nonblock, uchar cloexec)
{
    int sock_domain;
    int sock_type;

    if (swSocket_get_domain_and_type(type, &sock_domain, &sock_type) < 0)
    {
        swWarn("unknown socket type [%d]", type);
        errno = ESOCKTNOSUPPORT;
        return SW_ERR;
    }

#if defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
    int flags = 0;
    if (nonblock)
    {
        flags |= SOCK_NONBLOCK;
    }
    if (cloexec)
    {
        flags |= SOCK_CLOEXEC;
    }
    return socket(sock_domain, sock_type | flags, 0);
#else
    int sockfd = socket(sock_domain, sock_type, 0);
    if (sockfd < 0)
    {
        return SW_ERR;
    }
    if (!nonblock && !cloexec)
    {
        return sockfd;
    }
    if (swoole_fcntl_set_option(sockfd, nonblock ? 1 : -1, cloexec ? 1 : -1) < 0)
    {
        close(sockfd);
        return SW_ERR;
    }
    return sockfd;
#endif
}

swSocket* swSocket_new(int fd, enum swFd_type type)
{
    swSocket *socket = (swSocket *) sw_calloc(1, sizeof(*socket));
    if (!socket)
    {
        swSysWarn("calloc(1, %ld) failed", sizeof(*socket));
        return NULL;
    }
    socket->fd = fd;
    socket->fdtype = type;
    socket->removed = 1;
    return socket;
}

static void socket_free_defer(void *ptr)
{
    swSocket *sock = (swSocket *) ptr;
    if (sock->fd != -1 && close(sock->fd) != 0)
    {
        swSysWarn("close(%d) failed", sock->fd);
    }
    sw_free(sock);
}

void swSocket_free(swSocket *sock)
{
    if (SwooleTG.reactor)
    {
        sock->removed = 1;
        swoole_event_defer(socket_free_defer, sock);
    }
    else
    {
        socket_free_defer(sock);
    }
}

int swSocket_bind(swSocket *sock, const char *host, int *port)
{
    int ret;
    swSocketAddress address = {};

    int option = 1;
    if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int)) != 0)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SYSTEM_CALL_FAIL, "setsockopt(%d, SO_REUSEADDR) failed", sock->fd);
    }
    //UnixSocket
    if (sock->socket_type == SW_SOCK_UNIX_DGRAM || sock->socket_type == SW_SOCK_UNIX_STREAM)
    {
        unlink(host);
        address.addr.un.sun_family = AF_UNIX;
        strncpy(address.addr.un.sun_path, host, sizeof(address.addr.un.sun_path) - 1);
        ret = bind(sock->fd, (struct sockaddr *) &address.addr.un, sizeof(address.addr.un));
    }
    //IPv6
    else if (sock->socket_type > SW_SOCK_UDP)
    {
        if (inet_pton(AF_INET6, host, &address.addr.inet_v6.sin6_addr) < 0)
        {
            swSysWarn("inet_pton(AF_INET6, %s) failed", host);
            return SW_ERR;
        }
        address.addr.inet_v6.sin6_port = htons(*port);
        address.addr.inet_v6.sin6_family = AF_INET6;
        ret = bind(sock->fd, (struct sockaddr *) &address.addr.inet_v6, sizeof(address.addr.inet_v6));
        if (ret == 0 && *port == 0)
        {
            address.len = sizeof(address.addr.inet_v6);
            if (getsockname(sock->fd, (struct sockaddr *) &address.addr.inet_v6, &address.len) != -1)
            {
                *port = ntohs(address.addr.inet_v6.sin6_port);
            }
        }
    }
    //IPv4
    else
    {
        if (inet_pton(AF_INET, host, &address.addr.inet_v4.sin_addr) < 0)
        {
            swSysWarn("inet_pton(AF_INET, %s) failed", host);
            return SW_ERR;
        }
        address.addr.inet_v4.sin_port = htons(*port);
        address.addr.inet_v4.sin_family = AF_INET;
        ret = bind(sock->fd, (struct sockaddr *) &address.addr.inet_v4, sizeof(address.addr.inet_v4));
        if (ret == 0 && *port == 0)
        {
            address.len = sizeof(address.addr.inet_v4);
            if (getsockname(sock->fd, (struct sockaddr *) &address.addr.inet_v4, &address.len) != -1)
            {
                *port = ntohs(address.addr.inet_v4.sin_port);
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

int swSocket_set_buffer_size(swSocket *sock, uint32_t buffer_size)
{
    int fd = sock->fd;
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

int swSocket_set_timeout(swSocket *sock, double timeout)
{
    int ret;
    struct timeval timeo;
    timeo.tv_sec = (int) timeout;
    timeo.tv_usec = (int) ((timeout - timeo.tv_sec) * 1000 * 1000);
    ret = setsockopt(sock->fd, SOL_SOCKET, SO_SNDTIMEO, (void *) &timeo, sizeof(timeo));
    if (ret < 0)
    {
        swSysWarn("setsockopt(SO_SNDTIMEO) failed");
        return SW_ERR;
    }
    ret = setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, (void *) &timeo, sizeof(timeo));
    if (ret < 0)
    {
        swSysWarn("setsockopt(SO_RCVTIMEO) failed");
        return SW_ERR;
    }
    return SW_OK;
}

swSocket* swSocket_create_server(enum swSocket_type type, const char *address, int port, int backlog)
{
    int fd = swSocket_create(type, 0, 0);
    if (fd < 0)
    {
        swSysWarn("socket() failed");
        return nullptr;
    }
    swSocket *sock = swSocket_new(fd, SW_FD_STREAM_SERVER);
    if (!sock)
    {
        close(fd);
        return nullptr;
    }
    sock->socket_type = type;
    if (swSocket_bind(sock, address, &port) < 0)
    {
        swSocket_free(sock);
        return nullptr;
    }
    if (listen(fd, backlog) < 0)
    {
        swSysWarn("listen(%s:%d, %d) failed", address, port, backlog);
        swSocket_free(sock);
        return nullptr;
    }

    return sock;
}
