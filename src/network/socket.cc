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

#include "swoole_socket.h"

#include <assert.h>
#include <memory>

#include "swoole_api.h"
#include "swoole_log.h"
#include "swoole_ssl.h"

namespace swoole {
namespace network {

double Socket::default_dns_timeout = SW_SOCKET_DEFAULT_DNS_TIMEOUT;
double Socket::default_connect_timeout = SW_SOCKET_DEFAULT_CONNECT_TIMEOUT;
double Socket::default_read_timeout = SW_SOCKET_DEFAULT_READ_TIMEOUT;
double Socket::default_write_timeout = SW_SOCKET_DEFAULT_WRITE_TIMEOUT;
uint32_t Socket::default_buffer_size = SW_SOCKET_BUFFER_SIZE;

int Socket::sendfile_blocking(const char *filename, off_t offset, size_t length, double timeout) {
    int timeout_ms = timeout < 0 ? -1 : timeout * 1000;
    int file_fd = open(filename, O_RDONLY);
    if (file_fd < 0) {
        swSysWarn("open(%s) failed", filename);
        return SW_ERR;
    }

    if (length == 0) {
        struct stat file_stat;
        if (fstat(file_fd, &file_stat) < 0) {
            swSysWarn("fstat() failed");
            ::close(file_fd);
            return SW_ERR;
        }
        length = file_stat.st_size;
    } else {
        length = offset + length;
    }

    int n, sendn;
    while (offset < (off_t) length) {
        if (wait_event(timeout_ms, SW_EVENT_WRITE) < 0) {
            ::close(file_fd);
            return SW_ERR;
        } else {
            sendn = (length - offset > SW_SENDFILE_CHUNK_SIZE) ? SW_SENDFILE_CHUNK_SIZE : length - offset;
            n = ::swoole_sendfile(fd, file_fd, &offset, sendn);
            if (n <= 0) {
                ::close(file_fd);
                swSysWarn("sendfile(%d, %s) failed", fd, filename);
                return SW_ERR;
            } else {
                continue;
            }
        }
    }
    ::close(file_fd);
    return SW_OK;
}

/**
 * clear socket buffer.
 */
void Socket::clean() {
    char buf[2048];
    while (::recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
    };
}

/**
 * Wait socket can read or write.
 */
int Socket::wait_event(int timeout_ms, int events) {
    struct pollfd event;
    event.fd = fd;
    event.events = 0;

    if (timeout_ms < 0) {
        timeout_ms = -1;
    }

    if (events & SW_EVENT_READ) {
        event.events |= POLLIN;
    }
    if (events & SW_EVENT_WRITE) {
        event.events |= POLLOUT;
    }
    while (1) {
        int ret = poll(&event, 1, timeout_ms);
        if (ret == 0) {
            return SW_ERR;
        } else if (ret < 0 && errno != EINTR) {
            swSysWarn("poll() failed");
            return SW_ERR;
        } else {
            return SW_OK;
        }
    }
    return SW_OK;
}

ssize_t Socket::send_blocking(const void *__data, size_t __len) {
    ssize_t n = 0;
    ssize_t written = 0;

    while (written < (ssize_t) __len) {
#ifdef SW_USE_OPENSSL
        if (ssl) {
            n = swSSL_send(this, (char *) __data + written, __len - written);
        } else
#endif
        {
            n = ::send(fd, (char *) __data + written, __len - written, 0);
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            } else if (catch_error(errno) == SW_WAIT &&
                       wait_event((int) (send_timeout_ * 1000), SW_EVENT_WRITE) == SW_OK) {
                continue;
            } else {
                swSysWarn("send %d bytes failed", __len);
                return SW_ERR;
            }
        }
        written += n;
    }

    return written;
}

ssize_t Socket::recv_blocking(void *__data, size_t __len, int flags) {
    ssize_t ret;
    size_t read_bytes = 0;

    while (read_bytes != __len) {
        errno = 0;
        ret = ::recv(fd, (char *) __data + read_bytes, __len - read_bytes, flags);
        if (ret > 0) {
            read_bytes += ret;
        } else if (ret == 0) {
            return read_bytes;
        } else if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (catch_error(errno) == SW_WAIT && wait_event((int) (recv_timeout_ * 1000), SW_EVENT_READ) == SW_OK) {
                continue;
            }
            return ret;
        }
    }

    return read_bytes;
}

Socket *Socket::accept() {
    Socket *socket = new Socket();
    socket->removed = 1;
    socket->socket_type = socket_type;
    socket->info.len = sizeof(socket->info);
#ifdef HAVE_ACCEPT4
    int flags = SOCK_CLOEXEC;
    if (nonblock) {
        flags |= SOCK_NONBLOCK;
    }
    socket->fd = ::accept4(fd, (struct sockaddr *) &socket->info.addr, &socket->info.len, flags);
#else
    socket->fd = ::accept(fd, (struct sockaddr *) &socket->info.addr, &socket->info.len);
    if (socket->fd >= 0) {
        swoole_fcntl_set_option(socket->fd, nonblock, 1);
    }
#endif
    if (socket->fd < 0) {
        delete socket;
        return nullptr;
    }
    socket->info.type = socket_type;
    socket->nonblock = nonblock;
    socket->cloexec = 1;
    return socket;
}

ssize_t Socket::sendto_blocking(const Address &sa, const void *__buf, size_t __n, int flags) {
    ssize_t n = 0;

    for (int i = 0; i < SW_SOCKET_RETRY_COUNT; i++) {
        n = sendto(sa, __buf, __n, flags);
        if (n >= 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        if (catch_error(errno) == SW_WAIT && wait_event((int) (send_timeout_ * 1000), SW_EVENT_WRITE) == SW_OK) {
            continue;
        }
        break;
    }

    return n;
}

ssize_t Socket::recvfrom_blocking(char *__buf, size_t __len, int flags, Address *sa) {
    ssize_t n = 0;

    for (int i = 0; i < SW_SOCKET_RETRY_COUNT; i++) {
        n = recvfrom(__buf, __len, flags, sa);
        if (n >= 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        if (catch_error(errno) == SW_WAIT && wait_event((int) (recv_timeout_ * 1000), SW_EVENT_READ) == SW_OK) {
            continue;
        }
        break;
    }

    return n;
}

static void socket_free_defer(void *ptr) {
    Socket *sock = (Socket *) ptr;
    if (sock->fd != -1 && close(sock->fd) != 0) {
        swSysWarn("close(%d) failed", sock->fd);
    }
    delete sock;
}

void Socket::free() {
    if (swoole_event_is_available()) {
        removed = 1;
        swoole_event_defer(socket_free_defer, this);
    } else {
        socket_free_defer(this);
    }
}

int Socket::bind(const char *host, int *port) {
    int ret;
    Address address = {};
    size_t l_host = strlen(host);

    int option = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int)) < 0) {
        swSysWarn("setsockopt(%d, SO_REUSEADDR) failed", fd);
    }
    // UnixSocket
    if (socket_type == SW_SOCK_UNIX_DGRAM || socket_type == SW_SOCK_UNIX_STREAM) {
        if (l_host == 0 || l_host > sizeof(address.addr.un) - 1) {
            swWarn("bad unix socket file");
            errno = EINVAL;
            return SW_ERR;
        }
        unlink(host);
        address.addr.un.sun_family = AF_UNIX;
        strncpy(address.addr.un.sun_path, host, sizeof(address.addr.un.sun_path) - 1);
        ret = ::bind(fd, (struct sockaddr *) &address.addr.un, sizeof(address.addr.un));
    }
    // IPv6
    else if (socket_type == SW_SOCK_TCP6 || socket_type == SW_SOCK_UDP6) {
        if (l_host == 0) {
            host = "::";
        }
        if (inet_pton(AF_INET6, host, &address.addr.inet_v6.sin6_addr) < 0) {
            swSysWarn("inet_pton(AF_INET6, %s) failed", host);
            return SW_ERR;
        }
        address.addr.inet_v6.sin6_port = htons(*port);
        address.addr.inet_v6.sin6_family = AF_INET6;
        ret = ::bind(fd, (struct sockaddr *) &address.addr.inet_v6, sizeof(address.addr.inet_v6));
        if (ret == 0 && *port == 0) {
            address.len = sizeof(address.addr.inet_v6);
            if (getsockname(fd, (struct sockaddr *) &address.addr.inet_v6, &address.len) != -1) {
                *port = ntohs(address.addr.inet_v6.sin6_port);
            }
        }
    }
    // IPv4
    else if (socket_type == SW_SOCK_UDP || socket_type == SW_SOCK_TCP) {
        if (l_host == 0) {
            host = "0.0.0.0";
        }
        if (inet_pton(AF_INET, host, &address.addr.inet_v4.sin_addr) < 0) {
            swSysWarn("inet_pton(AF_INET, %s) failed", host);
            return SW_ERR;
        }
        address.addr.inet_v4.sin_port = htons(*port);
        address.addr.inet_v4.sin_family = AF_INET;
        ret = ::bind(fd, (struct sockaddr *) &address.addr.inet_v4, sizeof(address.addr.inet_v4));
        if (ret == 0 && *port == 0) {
            address.len = sizeof(address.addr.inet_v4);
            if (getsockname(fd, (struct sockaddr *) &address.addr.inet_v4, &address.len) != -1) {
                *port = ntohs(address.addr.inet_v4.sin_port);
            }
        }
    } else {
        errno = EINVAL;
        return -1;
    }

    // bind failed
    if (ret < 0) {
        return SW_ERR;
    }

    return ret;
}

bool Socket::set_buffer_size(uint32_t _buffer_size) {
    if (!set_send_buffer_size(_buffer_size)) {
        return false;
    }
    if (!set_recv_buffer_size(_buffer_size)) {
        return false;
    }
    return true;
}

bool Socket::set_recv_buffer_size(uint32_t _buffer_size) {
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &_buffer_size, sizeof(_buffer_size)) != 0) {
        swSysWarn("setsockopt(%d, SOL_SOCKET, SO_SNDBUF, %d) failed", fd, _buffer_size);
        return false;
    }
    return true;
}

bool Socket::set_send_buffer_size(uint32_t _buffer_size) {
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &_buffer_size, sizeof(_buffer_size)) != 0) {
        swSysWarn("setsockopt(%d, SOL_SOCKET, SO_RCVBUF, %d) failed", fd, _buffer_size);
        return false;
    }
    return true;
}

bool Socket::set_timeout(double timeout) {
    return set_recv_timeout(timeout) and set_send_timeout(timeout);
}

static inline bool _set_timeout(int fd, int type, double timeout) {
    int ret;
    struct timeval timeo;
    timeo.tv_sec = (int) timeout;
    timeo.tv_usec = (int) ((timeout - timeo.tv_sec) * 1000 * 1000);
    ret = setsockopt(fd, SOL_SOCKET, type, (void *) &timeo, sizeof(timeo));
    if (ret < 0) {
        swSysWarn("setsockopt(SO_SNDTIMEO, %s) failed", type == SO_SNDTIMEO ? "SEND" : "RECV");
        return false;
    } else {
        return true;
    }
}

bool Socket::set_recv_timeout(double timeout) {
    if (_set_timeout(fd, SO_SNDTIMEO, timeout)) {
        send_timeout_ = timeout;
        return true;
    } else {
        return false;
    }
}

bool Socket::set_send_timeout(double timeout) {
    if (_set_timeout(fd, SO_RCVTIMEO, timeout)) {
        recv_timeout_ = timeout;
        return true;
    } else {
        return false;
    }
}

int Socket::handle_sendfile(swBuffer_chunk *chunk) {
    int ret;
    SendfileRequest *task = (SendfileRequest *) chunk->store.ptr;

#ifdef HAVE_TCP_NOPUSH
    if (task->offset == 0 && tcp_nopush == 0) {
        // disable tcp_nodelay
        if (tcp_nodelay) {
            int tcp_nodelay = 0;
            if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const void *) &tcp_nodelay, sizeof(int)) != 0) {
                swSysWarn("setsockopt(TCP_NODELAY) failed");
            }
        }
        // enable tcp_nopush
        if (set_tcp_nopush(1) == -1) {
            swSysWarn("set_tcp_nopush() failed");
        }
    }
#endif

    int sendn =
        (task->length - task->offset > SW_SENDFILE_CHUNK_SIZE) ? SW_SENDFILE_CHUNK_SIZE : task->length - task->offset;

#ifdef SW_USE_OPENSSL
    if (ssl) {
        ret = swSSL_sendfile(this, task->fd, &task->offset, sendn);
    } else
#endif
    {
        ret = ::swoole_sendfile(fd, task->fd, &task->offset, sendn);
    }

    swTrace("ret=%d|task->offset=%ld|sendn=%d|filesize=%ld", ret, (long) task->offset, sendn, task->length);

    if (ret <= 0) {
        switch (catch_error(errno)) {
        case SW_ERROR:
            swSysWarn("sendfile(%s, %ld, %d) failed", task->filename, (long) task->offset, sendn);
            swBuffer_pop_chunk(out_buffer, chunk);
            return SW_OK;
        case SW_CLOSE:
            close_wait = 1;
            return SW_ERR;
        case SW_WAIT:
            send_wait = 1;
            return SW_ERR;
        default:
            break;
        }
    }

    // sendfile finish
    if ((size_t) task->offset >= task->length) {
        swBuffer_pop_chunk(out_buffer, chunk);

#ifdef HAVE_TCP_NOPUSH
        // disable tcp_nopush
        if (set_tcp_nopush(0) == -1) {
            swSysWarn("set_tcp_nopush() failed");
        }
        // enable tcp_nodelay
        if (tcp_nodelay) {
            int value = 1;
            if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const void *) &value, sizeof(int)) != 0) {
                swSysWarn("setsockopt(TCP_NODELAY) failed");
            }
        }
#endif
    }
    return SW_OK;
}

/**
 * send buffer to client
 */
int Socket::handle_send() {
    swBuffer *buffer = out_buffer;
    swBuffer_chunk *chunk = swBuffer_get_chunk(buffer);
    uint32_t sendn = chunk->length - chunk->offset;

    if (sendn == 0) {
        swBuffer_pop_chunk(buffer, chunk);
        return SW_OK;
    }

    ssize_t ret = send((char *) chunk->store.ptr + chunk->offset, sendn, 0);
    if (ret < 0) {
        switch (catch_error(errno)) {
        case SW_ERROR:
            swSysWarn("send to fd[%d] failed", fd);
            break;
        case SW_CLOSE:
            close_wait = 1;
            return SW_ERR;
        case SW_WAIT:
            send_wait = 1;
            return SW_ERR;
        default:
            break;
        }
        return SW_OK;
    }
    // chunk full send
    else if (ret == sendn || sendn == 0) {
        swBuffer_pop_chunk(buffer, chunk);
    } else {
        chunk->offset += ret;
        // kernel is not fully processing and socket buffer is full
        if (ret < sendn) {
            send_wait = 1;
            return SW_ERR;
        }
    }
    return SW_OK;
}

static void Socket_sendfile_destructor(swBuffer_chunk *chunk) {
    SendfileRequest *task = (SendfileRequest *) chunk->store.ptr;
    close(task->fd);
    sw_free(task->filename);
    sw_free(task);
}

int Socket::sendfile(const char *filename, off_t offset, size_t length) {
    int file_fd = open(filename, O_RDONLY);
    if (file_fd < 0) {
        swSysWarn("open(%s) failed", filename);
        return SW_OK;
    }

    struct stat file_stat;
    if (fstat(file_fd, &file_stat) < 0) {
        swSysWarn("fstat(%s) failed", filename);
        close(file_fd);
        return SW_ERR;
    }

    if (file_stat.st_size == 0) {
        swWarn("empty file[%s]", filename);
        close(file_fd);
        return SW_ERR;
    }

    if (out_buffer == nullptr) {
        out_buffer = swBuffer_new(SW_SEND_BUFFER_SIZE);
        if (out_buffer == nullptr) {
            return SW_ERR;
        }
    }

    swBuffer_chunk error_chunk;
    SendfileRequest *task = (SendfileRequest *) sw_malloc(sizeof(SendfileRequest));
    if (task == nullptr) {
        swWarn("malloc for SendFileTask failed");
        return SW_ERR;
    }
    sw_memset_zero(task, sizeof(SendfileRequest));

    task->filename = sw_strdup(filename);
    task->fd = file_fd;
    task->offset = offset;

    if (offset < 0 || (length + offset > (size_t) file_stat.st_size)) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_INVALID_PARAMS, "length or offset is invalid");
        error_chunk.store.ptr = task;
        Socket_sendfile_destructor(&error_chunk);
        return SW_OK;
    }
    if (length == 0) {
        task->length = file_stat.st_size;
    } else {
        task->length = length + offset;
    }

    swBuffer_chunk *chunk = swBuffer_new_chunk(out_buffer, SW_CHUNK_SENDFILE, 0);
    if (chunk == nullptr) {
        swWarn("get out_buffer chunk failed");
        error_chunk.store.ptr = task;
        Socket_sendfile_destructor(&error_chunk);
        return SW_ERR;
    }

    chunk->store.ptr = (void *) task;
    chunk->destroy = Socket_sendfile_destructor;

    return SW_OK;
}

ssize_t Socket::recv(void *__buf, size_t __n, int __flags) {
    ssize_t total_bytes = 0;

    do {
#ifdef SW_USE_OPENSSL
        if (ssl) {
            ssize_t retval = 0;
            while ((size_t) total_bytes < __n) {
                retval = swSSL_recv(this, ((char *) __buf) + total_bytes, __n - total_bytes);
                if (retval <= 0) {
                    if (total_bytes == 0) {
                        total_bytes = retval;
                    }
                    break;
                } else {
                    total_bytes += retval;
                    if (!(nonblock || (__flags & MSG_WAITALL))) {
                        break;
                    }
                }
            }
        } else
#endif
        {
            total_bytes = ::recv(fd, __buf, __n, __flags);
        }
    } while (total_bytes < 0 && errno == EINTR);

#ifdef SW_DEBUG
    if (total_bytes > 0) {
        total_recv_bytes += total_bytes;
    }
#endif

    if (total_bytes < 0 && catch_error(errno) == SW_WAIT && event_hup) {
        total_bytes = 0;
    }

    swTraceLog(SW_TRACE_SOCKET, "recv %ld/%ld bytes, errno=%d", total_bytes, __n, errno);

    return total_bytes;
}

ssize_t Socket::send(const void *__buf, size_t __n, int __flags) {
    ssize_t retval;

    do {
#ifdef SW_USE_OPENSSL
        if (ssl) {
            retval = swSSL_send(this, __buf, __n);
        } else
#endif
        {
            retval = ::send(fd, __buf, __n, __flags);
        }
    } while (retval < 0 && errno == EINTR);

#ifdef SW_DEBUG
    if (retval > 0) {
        total_send_bytes += retval;
    }
#endif

    swTraceLog(SW_TRACE_SOCKET, "send %ld/%ld bytes, errno=%d", retval, __n, errno);

    return retval;
}

ssize_t Socket::peek(void *__buf, size_t __n, int __flags) {
    ssize_t retval;
    __flags |= MSG_PEEK;
    do {
#ifdef SW_USE_OPENSSL
        if (ssl) {
            retval = SSL_peek(ssl, __buf, __n);
        } else
#endif
        {
            retval = ::recv(fd, __buf, __n, __flags);
        }
    } while (retval < 0 && errno == EINTR);

    swTraceLog(SW_TRACE_SOCKET, "peek %ld/%ld bytes, errno=%d", retval, __n, errno);

    return retval;
}

}  // namespace network

using network::Socket;

Socket *make_socket(enum swSocket_type type, enum swFd_type fdtype, int flags) {
    int sock_domain;
    int sock_type;

    if (Socket::get_domain_and_type(type, &sock_domain, &sock_type) < 0) {
        swWarn("unknown socket type [%d]", type);
        errno = ESOCKTNOSUPPORT;
        return nullptr;
    }

    bool nonblock = flags & SW_SOCK_NONBLOCK;
    bool cloexec = flags & SW_SOCK_CLOEXEC;

#if defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
    int sock_flags = 0;
    if (nonblock) {
        sock_flags |= SOCK_NONBLOCK;
    }
    if (cloexec) {
        sock_flags |= SOCK_CLOEXEC;
    }
    int sockfd = socket(sock_domain, sock_type | sock_flags, 0);
    if (sockfd < 0) {
        return nullptr;
    }
#else
    int sockfd = socket(sock_domain, sock_type, 0);
    if (sockfd < 0) {
        return nullptr;
    }
    if (nonblock || cloexec) {
        if (swoole_fcntl_set_option(sockfd, nonblock ? 1 : -1, cloexec ? 1 : -1) < 0) {
            close(sockfd);
            return nullptr;
        }
    }
#endif
    auto _socket = swoole::make_socket(sockfd, fdtype);
    _socket->nonblock = nonblock;
    _socket->cloexec = cloexec;
    _socket->socket_type = type;
    return _socket;
}

Socket *make_server_socket(enum swSocket_type type, const char *address, int port, int backlog) {
    Socket *sock = swoole::make_socket(type, SW_FD_STREAM_SERVER, SW_SOCK_CLOEXEC);
    if (sock == nullptr) {
        swSysWarn("socket() failed");
        return nullptr;
    }
    if (sock->bind(address, &port) < 0) {
        sock->free();
        return nullptr;
    }
    if (Socket::is_stream(type) && listen(sock->fd, backlog) < 0) {
        swSysWarn("listen(%s:%d, %d) failed", address, port, backlog);
        sock->free();
        return nullptr;
    }
    return sock;
}

Socket *make_socket(int fd, enum swFd_type type) {
    Socket *socket = new Socket();
    socket->fd = fd;
    socket->fdtype = type;
    socket->removed = 1;
    return socket;
}

}  // namespace swoole
