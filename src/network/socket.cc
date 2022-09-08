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
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#include "swoole_socket.h"

#include <memory>

#include "swoole_api.h"
#include "swoole_util.h"
#include "swoole_string.h"

namespace swoole {
namespace network {

double Socket::default_dns_timeout = SW_SOCKET_DEFAULT_DNS_TIMEOUT;
double Socket::default_connect_timeout = SW_SOCKET_DEFAULT_CONNECT_TIMEOUT;
double Socket::default_read_timeout = SW_SOCKET_DEFAULT_READ_TIMEOUT;
double Socket::default_write_timeout = SW_SOCKET_DEFAULT_WRITE_TIMEOUT;
uint32_t Socket::default_buffer_size = SW_SOCKET_BUFFER_SIZE;

IOVector::IOVector(struct iovec *_iov, int _iovcnt) {
    iov = new iovec[_iovcnt + _iovcnt];
    iov_iterator = iov + _iovcnt;
    count = remain_count = _iovcnt;

    memcpy(iov, _iov, sizeof(*_iov) * _iovcnt);
    memcpy(iov_iterator, _iov, sizeof(*_iov) * _iovcnt);
}

IOVector::~IOVector() {
    delete[] iov;
}

void IOVector::update_iterator(ssize_t __n) {
    size_t total_bytes = 0;
    size_t _offset_bytes = 0;
    int _index = 0;

    if (__n <= 0 || remain_count == 0) {
        return;
    }

    SW_LOOP_N(remain_count) {
        total_bytes += iov_iterator[i].iov_len;
        if ((ssize_t) total_bytes >= __n) {
            _offset_bytes = iov_iterator[i].iov_len - (total_bytes - __n);
            _index = i;

            if (_offset_bytes == iov_iterator[i].iov_len) {
                _index++;
                _offset_bytes = 0;
            }
            // update remain_count, index, offset_bytes
            remain_count -= _index;
            index += _index;
            offset_bytes = i > 0 ? 0 : offset_bytes;
            offset_bytes += _offset_bytes;
            if (remain_count == 0) {
                // iov should not be modified, prevent valgrind from checking for invalid read
                return;
            }
            iov_iterator += _index;
            iov_iterator->iov_base = reinterpret_cast<char *>(iov_iterator->iov_base) + _offset_bytes;
            iov_iterator->iov_len = iov_iterator->iov_len - _offset_bytes;

            return;
        }
    }

    // represents the length of __n greater than total_bytes
    abort();
}

int Socket::sendfile_blocking(const char *filename, off_t offset, size_t length, double timeout) {
    int timeout_ms = timeout < 0 ? -1 : timeout * 1000;

    File file(filename, O_RDONLY);
    if (!file.ready()) {
        swoole_sys_warning("open(%s) failed", filename);
        return SW_ERR;
    }

    if (length == 0) {
        FileStatus file_stat;
        if (!file.stat(&file_stat)) {
            return SW_ERR;
        }
        length = file_stat.st_size;
    } else {
        length = offset + length;
    }

    int n, sendn;
    while (offset < (off_t) length) {
        if (wait_event(timeout_ms, SW_EVENT_WRITE) < 0) {
            return SW_ERR;
        } else {
            sendn = (length - offset > SW_SENDFILE_CHUNK_SIZE) ? SW_SENDFILE_CHUNK_SIZE : length - offset;
            n = ::swoole_sendfile(fd, file.get_fd(), &offset, sendn);
            if (n <= 0) {
                swoole_sys_warning("sendfile(%d, %s) failed", fd, filename);
                return SW_ERR;
            } else {
                continue;
            }
        }
    }
    return SW_OK;
}

ssize_t Socket::writev_blocking(const struct iovec *iov, size_t iovcnt) {
    while (1) {
        ssize_t n = writev(iov, iovcnt);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            } else if (catch_write_error(errno) == SW_WAIT &&
                       wait_event((int) (send_timeout_ * 1000), SW_EVENT_WRITE) == SW_OK) {
                continue;
            } else {
                swoole_sys_warning("send %lu bytes failed", iov[1].iov_len);
                return SW_ERR;
            }
        } else {
            return n;
        }
    }
    return -1;
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
            swoole_set_last_error(SW_ERROR_SOCKET_POLL_TIMEOUT);
            return SW_ERR;
        } else if (ret < 0 && errno != EINTR) {
            swoole_sys_warning("poll() failed");
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
            n = ssl_send((char *) __data + written, __len - written);
        } else
#endif
        {
            n = ::send(fd, (char *) __data + written, __len - written, 0);
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            } else if (catch_write_error(errno) == SW_WAIT &&
                       wait_event((int) (send_timeout_ * 1000), SW_EVENT_WRITE) == SW_OK) {
                continue;
            } else {
                swoole_sys_warning("send %lu bytes failed", __len);
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
            if (catch_read_error(errno) == SW_WAIT &&
                wait_event((int) (recv_timeout_ * 1000), SW_EVENT_READ) == SW_OK) {
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
        set_fd_option(nonblock, 1);
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
        if (catch_write_error(errno) == SW_WAIT && wait_event((int) (send_timeout_ * 1000), SW_EVENT_WRITE) == SW_OK) {
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
        if (catch_read_error(errno) == SW_WAIT && wait_event((int) (recv_timeout_ * 1000), SW_EVENT_READ) == SW_OK) {
            continue;
        }
        break;
    }

    return n;
}

static void socket_free_defer(void *ptr) {
    Socket *sock = (Socket *) ptr;
    if (sock->fd != -1 && close(sock->fd) != 0) {
        swoole_sys_warning("close(%d) failed", sock->fd);
    }
    delete sock;
}

void Socket::free() {
    if (recv_timer) {
        swoole_timer_del(recv_timer);
    }
    if (send_timer) {
        swoole_timer_del(send_timer);
    }
    if (in_buffer) {
        delete in_buffer;
    }
    if (out_buffer) {
        delete out_buffer;
    }
    if (swoole_event_is_available()) {
        removed = 1;
        swoole_event_defer(socket_free_defer, this);
    } else {
        socket_free_defer(this);
    }
}

int Socket::bind(const std::string &_host, int *port) {
    int ret;
    Address address = {};
    size_t l_host = _host.length();
    const char *host = _host.c_str();

    if (set_reuse_addr() < 0) {
        swoole_sys_warning("setsockopt(%d, SO_REUSEADDR) failed", fd);
    }
    // UnixSocket
    if (socket_type == SW_SOCK_UNIX_DGRAM || socket_type == SW_SOCK_UNIX_STREAM) {
        if (l_host == 0 || l_host > sizeof(address.addr.un) - 1) {
            swoole_warning("bad unix socket file");
            errno = EINVAL;
            return SW_ERR;
        }
        unlink(host);
        address.addr.un.sun_family = AF_UNIX;
        swoole_strlcpy(address.addr.un.sun_path, host, sizeof(address.addr.un.sun_path));
        ret = ::bind(fd, (struct sockaddr *) &address.addr.un, sizeof(address.addr.un));
    }
    // IPv6
    else if (socket_type == SW_SOCK_TCP6 || socket_type == SW_SOCK_UDP6) {
        if (l_host == 0) {
            host = "::";
        }
        if (inet_pton(AF_INET6, host, &address.addr.inet_v6.sin6_addr) < 0) {
            swoole_sys_warning("inet_pton(AF_INET6, %s) failed", host);
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
            swoole_sys_warning("inet_pton(AF_INET, %s) failed", host);
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
    if (set_option(SOL_SOCKET, SO_RCVBUF, _buffer_size) != 0) {
        swoole_sys_warning("setsockopt(%d, SOL_SOCKET, SO_SNDBUF, %d) failed", fd, _buffer_size);
        return false;
    }
    return true;
}

bool Socket::set_send_buffer_size(uint32_t _buffer_size) {
    if (set_option(SOL_SOCKET, SO_SNDBUF, _buffer_size) != 0) {
        swoole_sys_warning("setsockopt(%d, SOL_SOCKET, SO_RCVBUF, %d) failed", fd, _buffer_size);
        return false;
    }
    return true;
}

bool Socket::set_timeout(double timeout) {
    return set_recv_timeout(timeout) and set_send_timeout(timeout);
}

static bool _set_timeout(int fd, int type, double timeout) {
    int ret;
    struct timeval timeo;
    timeo.tv_sec = (int) timeout;
    timeo.tv_usec = (int) ((timeout - timeo.tv_sec) * 1000 * 1000);
    ret = setsockopt(fd, SOL_SOCKET, type, (void *) &timeo, sizeof(timeo));
    if (ret < 0) {
        swoole_sys_warning("setsockopt(SO_SNDTIMEO, %s) failed", type == SO_SNDTIMEO ? "SEND" : "RECV");
        return false;
    } else {
        return true;
    }
}

static bool _fcntl_set_option(int sock, int nonblock, int cloexec) {
    int opts, ret;

    if (nonblock >= 0) {
        do {
            opts = fcntl(sock, F_GETFL);
        } while (opts < 0 && errno == EINTR);

        if (opts < 0) {
            swoole_sys_warning("fcntl(%d, GETFL) failed", sock);
        }

        if (nonblock) {
            opts = opts | O_NONBLOCK;
        } else {
            opts = opts & ~O_NONBLOCK;
        }

        do {
            ret = fcntl(sock, F_SETFL, opts);
        } while (ret < 0 && errno == EINTR);

        if (ret < 0) {
            swoole_sys_warning("fcntl(%d, SETFL, opts) failed", sock);
            return false;
        }
    }

#ifdef FD_CLOEXEC
    if (cloexec >= 0) {
        do {
            opts = fcntl(sock, F_GETFD);
        } while (opts < 0 && errno == EINTR);

        if (opts < 0) {
            swoole_sys_warning("fcntl(%d, GETFL) failed", sock);
        }

        if (cloexec) {
            opts = opts | FD_CLOEXEC;
        } else {
            opts = opts & ~FD_CLOEXEC;
        }

        do {
            ret = fcntl(sock, F_SETFD, opts);
        } while (ret < 0 && errno == EINTR);

        if (ret < 0) {
            swoole_sys_warning("fcntl(%d, SETFD, opts) failed", sock);
            return false;
        }
    }
#endif

    return true;
}

bool Socket::set_fd_option(int _nonblock, int _cloexec) {
    if (_fcntl_set_option(fd, _nonblock, _cloexec)) {
        nonblock = _nonblock;
        cloexec = _cloexec;
        return true;
    } else {
        return false;
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

int Socket::handle_sendfile() {
    int ret;
    Buffer *buffer = out_buffer;
    BufferChunk *chunk = buffer->front();
    SendfileRequest *task = (SendfileRequest *) chunk->value.object;

    if (task->offset == 0) {
        cork();
    }

    size_t sendn =
        (task->length - task->offset > SW_SENDFILE_CHUNK_SIZE) ? SW_SENDFILE_CHUNK_SIZE : task->length - task->offset;

#ifdef SW_USE_OPENSSL
    if (ssl) {
        ret = ssl_sendfile(task->file, &task->offset, sendn);
    } else
#endif
    {
        ret = ::swoole_sendfile(fd, task->file.get_fd(), &task->offset, sendn);
    }

    swoole_trace("ret=%d|task->offset=%ld|sendn=%lu|filesize=%lu", ret, (long) task->offset, sendn, task->length);

    if (ret <= 0) {
        switch (catch_write_error(errno)) {
        case SW_ERROR:
            swoole_sys_warning(
                "sendfile(%s, %ld, %zu) failed", task->file.get_path().c_str(), (long) task->offset, sendn);
            buffer->pop();
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
    } else {
        if (send_timer) {
            last_sent_time = time<std::chrono::milliseconds>(true);
        }
    }

    // sendfile completed
    if ((size_t) task->offset >= task->length) {
        buffer->pop();
        uncork();
    }

    return SW_OK;
}

/**
 * send buffer to client
 */
int Socket::handle_send() {
    Buffer *buffer = out_buffer;
    BufferChunk *chunk = buffer->front();
    uint32_t sendn = chunk->length - chunk->offset;

    if (sendn == 0) {
        buffer->pop();
        return SW_OK;
    }

    ssize_t ret = send(chunk->value.ptr + chunk->offset, sendn, 0);
    if (ret < 0) {
        switch (catch_write_error(errno)) {
        case SW_ERROR:
            swoole_sys_warning("send to fd[%d] failed", fd);
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
        buffer->pop();
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

static void Socket_sendfile_destructor(BufferChunk *chunk) {
    SendfileRequest *task = (SendfileRequest *) chunk->value.object;
    delete task;
}

int Socket::sendfile(const char *filename, off_t offset, size_t length) {
    std::unique_ptr<SendfileRequest> task(new SendfileRequest(filename, offset, length));
    if (!task->file.ready()) {
        swoole_sys_warning("open(%s) failed", filename);
        return SW_OK;
    }

    FileStatus file_stat;
    if (!task->file.stat(&file_stat)) {
        swoole_sys_warning("fstat(%s) failed", filename);
        return SW_ERR;
    }

    if (file_stat.st_size == 0) {
        swoole_warning("empty file[%s]", filename);
        return SW_ERR;
    }

    if (out_buffer == nullptr) {
        out_buffer = new Buffer(SW_SEND_BUFFER_SIZE);
        if (out_buffer == nullptr) {
            return SW_ERR;
        }
    }

    if (offset < 0 || (length + offset > (size_t) file_stat.st_size)) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_INVALID_PARAMS, "length or offset is invalid");
        return SW_OK;
    }
    if (length == 0) {
        task->length = file_stat.st_size;
    } else {
        task->length = length + offset;
    }

    BufferChunk *chunk = out_buffer->alloc(BufferChunk::TYPE_SENDFILE, 0);
    chunk->value.object = task.release();
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
                retval = ssl_recv(((char *) __buf) + total_bytes, __n - total_bytes);
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

    if (total_bytes > 0) {
        total_recv_bytes += total_bytes;
        if (recv_timer) {
            last_received_time = time<std::chrono::milliseconds>(true);
        }
    }

    // The POLLHUP event is triggered, but Socket::recv returns EAGAIN
    if (total_bytes < 0 && catch_read_error(errno) == SW_WAIT && event_hup) {
        total_bytes = 0;
    }

    swoole_trace_log(SW_TRACE_SOCKET, "recv %ld/%ld bytes, errno=%d", total_bytes, __n, errno);

    return total_bytes;
}

ssize_t Socket::send(const void *__buf, size_t __n, int __flags) {
    ssize_t retval;

    do {
#ifdef SW_USE_OPENSSL
        if (ssl) {
            retval = ssl_send(__buf, __n);
        } else
#endif
        {
            retval = ::send(fd, __buf, __n, __flags);
        }
    } while (retval < 0 && errno == EINTR);

    if (retval > 0) {
        total_send_bytes += retval;
        if (send_timer) {
            last_sent_time = time<std::chrono::milliseconds>(true);
        }
    }

    swoole_trace_log(SW_TRACE_SOCKET, "send %ld/%ld bytes, errno=%d", retval, __n, errno);

    return retval;
}

ssize_t Socket::send_async(const void *__buf, size_t __n) {
    if (!swoole_event_is_available()) {
        return send_blocking(__buf, __n);
    } else {
        return swoole_event_write(this, __buf, __n);
    }
}

ssize_t Socket::readv(IOVector *io_vector) {
    ssize_t retval;

    do {
#ifdef SW_USE_OPENSSL
        if (ssl) {
            retval = ssl_readv(io_vector);
        } else
#endif
        {
            retval = ::readv(fd, io_vector->get_iterator(), io_vector->get_remain_count());
            io_vector->update_iterator(retval);
        }
    } while (retval < 0 && errno == EINTR);

    return retval;
}

ssize_t Socket::writev(IOVector *io_vector) {
    ssize_t retval;

    do {
#ifdef SW_USE_OPENSSL
        if (ssl) {
            retval = ssl_writev(io_vector);
        } else
#endif
        {
            retval = ::writev(fd, io_vector->get_iterator(), io_vector->get_remain_count());
            io_vector->update_iterator(retval);
        }
    } while (retval < 0 && errno == EINTR);

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

    swoole_trace_log(SW_TRACE_SOCKET, "peek %ld/%ld bytes, errno=%d", retval, __n, errno);

    return retval;
}

#ifdef SW_USE_OPENSSL

#ifndef X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
static int ssl_check_name(const char *name, ASN1_STRING *pattern) {
    char *s, *end;
    size_t slen, plen;

    s = (char *) name;
    slen = strlen(name);

    uchar *p = ASN1_STRING_data(pattern);
    plen = ASN1_STRING_length(pattern);

    if (swoole_strcaseeq(s, slen, (char *) p, plen)) {
        return SW_OK;
    }

    if (plen > 2 && p[0] == '*' && p[1] == '.') {
        plen -= 1;
        p += 1;

        end = s + slen;
        s = swoole_strlchr(s, end, '.');

        if (s == nullptr) {
            return SW_ERR;
        }

        slen = end - s;

        if (swoole_strcaseeq(s, slen, (char *) p, plen)) {
            return SW_OK;
        }
    }
    return SW_ERR;
}
#endif

bool Socket::ssl_check_host(const char *tls_host_name) {
    X509 *cert = ssl_get_peer_certificate();
    if (cert == nullptr) {
        return false;
    }
#ifdef X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
    /* X509_check_host() is only available in OpenSSL 1.0.2+ */
    if (X509_check_host(cert, tls_host_name, strlen(tls_host_name), 0, nullptr) != 1) {
        swoole_warning("X509_check_host(): no match");
        goto _failed;
    }
    goto _found;
#else
    int n, i;
    X509_NAME *sname;
    ASN1_STRING *str;
    X509_NAME_ENTRY *entry;
    GENERAL_NAME *altname;
    STACK_OF(GENERAL_NAME) * altnames;

    /*
     * As per RFC6125 and RFC2818, we check subjectAltName extension,
     * and if it's not present - commonName in Subject is checked.
     */
    altnames = (STACK_OF(GENERAL_NAME) *) X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);

    if (altnames) {
        n = sk_GENERAL_NAME_num(altnames);

        for (i = 0; i < n; i++) {
            altname = sk_GENERAL_NAME_value(altnames, i);

            if (altname->type != GEN_DNS) {
                continue;
            }

            str = altname->d.dNSName;
            swoole_trace("SSL subjectAltName: \"%.*s\"", ASN1_STRING_length(str), ASN1_STRING_data(str));

            if (ssl_check_name(tls_host_name, str) == SW_OK) {
                swoole_trace("SSL subjectAltName: match");
                GENERAL_NAMES_free(altnames);
                goto _found;
            }
        }

        swoole_trace("SSL subjectAltName: no match");
        GENERAL_NAMES_free(altnames);
        goto _failed;
    }

    /*
     * If there is no subjectAltName extension, check commonName
     * in Subject.  While RFC2818 requires to only check "most specific"
     * CN, both Apache and OpenSSL check all CNs, and so do we.
     */
    sname = X509_get_subject_name(cert);

    if (sname == nullptr) {
        goto _failed;
    }

    i = -1;
    for (;;) {
        i = X509_NAME_get_index_by_NID(sname, NID_commonName, i);

        if (i < 0) {
            break;
        }

        entry = X509_NAME_get_entry(sname, i);
        str = X509_NAME_ENTRY_get_data(entry);

        swoole_trace("SSL commonName: \"%.*s\"", ASN1_STRING_length(str), ASN1_STRING_data(str));

        if (ssl_check_name(tls_host_name, str) == SW_OK) {
            swoole_trace("SSL commonName: match");
            goto _found;
        }
    }
    swoole_trace("SSL commonName: no match");
#endif

_failed:
    X509_free(cert);
    return false;

_found:
    X509_free(cert);
    return true;
}

bool Socket::ssl_verify(bool allow_self_signed) {
    long err = SSL_get_verify_result(ssl);
    switch (err) {
    case X509_V_OK:
        break;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        if (allow_self_signed) {
            break;
        } else {
            swoole_error_log(
                SW_LOG_NOTICE, SW_ERROR_SSL_VERIFY_FAILED, "self signed certificate from fd#%d is not allowed", fd);
            return false;
        }
    default:
        swoole_error_log(SW_LOG_NOTICE,
                         SW_ERROR_SSL_VERIFY_FAILED,
                         "can not verify peer from fd#%d with error#%ld: %s",
                         fd,
                         err,
                         X509_verify_cert_error_string(err));
        return false;
    }

    return true;
}

X509 *Socket::ssl_get_peer_certificate() {
    if (!ssl) {
        return NULL;
    }
    return SSL_get_peer_certificate(ssl);
}

STACK_OF(X509) * Socket::ssl_get_peer_cert_chain() {
    if (!ssl) {
        return NULL;
    }
    return SSL_get_peer_cert_chain(ssl);
}

static int _ssl_read_x509_file(X509 *cert, char *buffer, size_t length) {
    long len;
    BIO *bio = BIO_new(BIO_s_mem());
    ON_SCOPE_EXIT {
        BIO_free(bio);
    };

    if (bio == nullptr) {
        swoole_warning("BIO_new() failed");
        return -1;
    }

    if (PEM_write_bio_X509(bio, cert) == 0) {
        swoole_warning("PEM_write_bio_X509() failed");
        return -1;
    }

    len = BIO_pending(bio);
    if (len < 0 && len > (long) length) {
        swoole_warning("certificate length[%ld] is too big", len);
        return -1;
    }
    return BIO_read(bio, buffer, len);
}

std::vector<std::string> Socket::ssl_get_peer_cert_chain(int limit) {
    std::vector<std::string> list;
    STACK_OF(X509) *chain = ssl_get_peer_cert_chain();
    if (chain == nullptr) {
        return list;
    }
    auto n = sk_X509_num(chain);

#ifdef OPENSSL_IS_BORINGSSL
    n = std::min((int) n, limit);
#else
    n = std::min(n, limit);
#endif

    SW_LOOP_N(n) {
        X509 *cert = sk_X509_value(chain, i);
        auto n = _ssl_read_x509_file(cert, sw_tg_buffer()->str, sw_tg_buffer()->size);
        if (n > 0) {
            list.emplace_back(sw_tg_buffer()->str, n);
        }
    }
    return list;
}

bool Socket::ssl_get_peer_certificate(String *buf) {
    int n = ssl_get_peer_certificate(buf->str, buf->size);
    if (n < 0) {
        return false;
    } else {
        buf->length = n;
        return true;
    }
}

int Socket::ssl_get_peer_certificate(char *buffer, size_t length) {
    X509 *cert = ssl_get_peer_certificate();
    if (cert == nullptr) {
        return SW_ERR;
    }
    ON_SCOPE_EXIT {
        if (cert) {
            X509_free(cert);
        }
    };
    return _ssl_read_x509_file(cert, buffer, length);
}

const char *Socket::ssl_get_error_reason(int *reason) {
    int error = ERR_get_error();
    *reason = ERR_GET_REASON(error);
    return ERR_reason_error_string(error);
}

ReturnCode Socket::ssl_accept() {
    ssl_clear_error();

    int n = SSL_accept(ssl);
    /**
     * The TLS/SSL handshake was successfully completed
     */
    if (n == 1) {
        ssl_state = SW_SSL_STATE_READY;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS
        if (ssl->s3) {
            ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
        }
#endif
#endif
        return SW_READY;
    }
    /**
     * The TLS/SSL handshake was not successful but was shutdown.
     */
    else if (n == 0) {
        return SW_ERROR;
    }

    long err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_WANT_READ) {
        ssl_want_read = 1;
        ssl_want_write = 0;
        return SW_WAIT;
    } else if (err == SSL_ERROR_WANT_WRITE) {
        ssl_want_read = 0;
        ssl_want_write = 1;
        return SW_WAIT;
    } else if (err == SSL_ERROR_SSL) {
        int reason;
        const char *error_string = ssl_get_error_reason(&reason);
        swoole_warning("bad SSL client[%s:%d], reason=%d, error_string=%s",
                       info.get_ip(),
                       info.get_port(),
                       reason,
                       error_string ? error_string : "(none)");
        return SW_ERROR;
    } else if (err == SSL_ERROR_SYSCALL) {
#ifdef SW_SUPPORT_DTLS
        if (dtls && errno == 0) {
            ssl_want_read = 1;
            return SW_WAIT;
        }
#endif
        return SW_ERROR;
    }
    swoole_warning("SSL_do_handshake() failed. Error: %s[%ld|%d]", strerror(errno), err, errno);
    return SW_ERROR;
}

int Socket::ssl_connect() {
    ssl_clear_error();

    int n = SSL_connect(ssl);
    if (n == 1) {
        ssl_state = SW_SSL_STATE_READY;

#ifdef SW_LOG_TRACE_OPEN
        const char *ssl_version = SSL_get_version(ssl);
        const char *ssl_cipher = SSL_get_cipher_name(ssl);
        swoole_trace_log(SW_TRACE_SSL, "connected (%s %s)", ssl_version, ssl_cipher);
#endif

        return SW_OK;
    }

    long err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_WANT_READ) {
        ssl_want_read = 1;
        ssl_want_write = 0;
        ssl_state = SW_SSL_STATE_WAIT_STREAM;
        return SW_OK;
    } else if (err == SSL_ERROR_WANT_WRITE) {
        ssl_want_read = 0;
        ssl_want_write = 1;
        ssl_state = SW_SSL_STATE_WAIT_STREAM;
        return SW_OK;
    } else if (err == SSL_ERROR_ZERO_RETURN) {
        swoole_debug("SSL_connect(fd=%d) closed", fd);
        return SW_ERR;
    } else if (err == SSL_ERROR_SYSCALL) {
        if (n) {
            swoole_set_last_error(errno);
            return SW_ERR;
        }
    }

    long err_code = ERR_get_error();
    ERR_error_string_n(err_code, sw_tg_buffer()->str, sw_tg_buffer()->size);
    swoole_notice("connect to SSL server[%s:%d] failed. Error: %s[%ld|%d]",
                  info.get_ip(),
                  info.get_port(),
                  sw_tg_buffer()->str,
                  err,
                  ERR_GET_REASON(err_code));

    return SW_ERR;
}

int Socket::ssl_sendfile(const File &fp, off_t *_offset, size_t _size) {
    char buf[SW_BUFFER_SIZE_BIG];
    ssize_t readn = _size > sizeof(buf) ? sizeof(buf) : _size;

    ssize_t n = fp.pread(buf, readn, *_offset);
    if (n > 0) {
        ssize_t ret = ssl_send(buf, n);
        if (ret < 0) {
            if (catch_write_error(errno) == SW_ERROR) {
                swoole_sys_warning("write() failed");
            }
        } else {
            *_offset += ret;
        }
        swoole_trace_log(SW_TRACE_REACTOR, "fd=%d, readn=%ld, n=%ld, ret=%ld", fd, readn, n, ret);
        return ret;
    } else {
        swoole_sys_warning("pread() failed");
        return SW_ERR;
    }
}

bool Socket::ssl_shutdown() {
    if (ssl_closed_) {
        return false;
    }
    if (SSL_in_init(ssl)) {
        return false;
    }
    /**
     * If the peer close first, local should be set to quiet mode and do not send any data,
     * otherwise the peer will send RST segment.
     */
    if (ssl_quiet_shutdown) {
        SSL_set_quiet_shutdown(ssl, 1);
    }

    int mode = SSL_get_shutdown(ssl);
    SSL_set_shutdown(ssl, mode | SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);

    int n = SSL_shutdown(ssl);
    ssl_closed_ = 1;
    swoole_trace("SSL_shutdown: %d", n);

    int sslerr = 0;
    /* before 0.9.8m SSL_shutdown() returned 0 instead of -1 on errors */
    if (n != 1 && ERR_peek_error()) {
        sslerr = SSL_get_error(ssl, n);
        swoole_trace("SSL_get_error: %d", sslerr);
    }

    if (!(n == 1 || sslerr == 0 || sslerr == SSL_ERROR_ZERO_RETURN)) {
        int reason;
        const char *error_string = ssl_get_error_reason(&reason);
        swoole_warning("SSL_shutdown() failed, reason=%d, error_string=%s", reason, error_string);
        return false;
    }

    return true;
}

void Socket::ssl_close() {
    /*
     * OpenSSL 1.0.2f complains if SSL_shutdown() is called during
     * an SSL handshake, while previous versions always return 0.
     * Avoid calling SSL_shutdown() if handshake wasn't completed.
     */
    if (!ssl_closed_) {
        ssl_shutdown();
    }
    SSL_free(ssl);
    ssl = nullptr;
}

void Socket::ssl_catch_error() {
    int level = SW_LOG_NOTICE;
    int reason = ERR_GET_REASON(ERR_peek_error());

#if 0
    /* handshake failures */
    switch (reason)
    {
    case SSL_R_BAD_CHANGE_CIPHER_SPEC: /*  103 */
    case SSL_R_BLOCK_CIPHER_PAD_IS_WRONG: /*  129 */
    case SSL_R_DIGEST_CHECK_FAILED: /*  149 */
    case SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST: /*  151 */
    case SSL_R_EXCESSIVE_MESSAGE_SIZE: /*  152 */
    case SSL_R_LENGTH_MISMATCH:/*  159 */
    case SSL_R_NO_CIPHERS_PASSED:/*  182 */
    case SSL_R_NO_CIPHERS_SPECIFIED:/*  183 */
    case SSL_R_NO_COMPRESSION_SPECIFIED: /*  187 */
    case SSL_R_NO_SHARED_CIPHER:/*  193 */
    case SSL_R_RECORD_LENGTH_MISMATCH: /*  213 */
#ifdef SSL_R_PARSE_TLSEXT
    case SSL_R_PARSE_TLSEXT:/*  227 */
#endif
    case SSL_R_UNEXPECTED_MESSAGE:/*  244 */
    case SSL_R_UNEXPECTED_RECORD:/*  245 */
    case SSL_R_UNKNOWN_ALERT_TYPE: /*  246 */
    case SSL_R_UNKNOWN_PROTOCOL:/*  252 */
    case SSL_R_WRONG_VERSION_NUMBER:/*  267 */
    case SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC: /*  281 */
#ifdef SSL_R_RENEGOTIATE_EXT_TOO_LONG
    case SSL_R_RENEGOTIATE_EXT_TOO_LONG:/*  335 */
    case SSL_R_RENEGOTIATION_ENCODING_ERR:/*  336 */
    case SSL_R_RENEGOTIATION_MISMATCH:/*  337 */
#endif
#ifdef SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED
    case SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED: /*  338 */
#endif
#ifdef SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING
    case SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING:/*  345 */
#endif
#ifdef SSL_R_INAPPROPRIATE_FALLBACK
    case SSL_R_INAPPROPRIATE_FALLBACK: /*  373 */
#endif
    case 1000:/* SSL_R_SSLV3_ALERT_CLOSE_NOTIFY */
    case SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE:/* 1010 */
    case SSL_R_SSLV3_ALERT_BAD_RECORD_MAC:/* 1020 */
    case SSL_R_TLSV1_ALERT_DECRYPTION_FAILED:/* 1021 */
    case SSL_R_TLSV1_ALERT_RECORD_OVERFLOW:/* 1022 */
    case SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE:/* 1030 */
    case SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE:/* 1040 */
    case SSL_R_SSLV3_ALERT_NO_CERTIFICATE:/* 1041 */
    case SSL_R_SSLV3_ALERT_BAD_CERTIFICATE:/* 1042 */
    case SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE: /* 1043 */
    case SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED:/* 1044 */
    case SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED:/* 1045 */
    case SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN:/* 1046 */
    case SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER:/* 1047 */
    case SSL_R_TLSV1_ALERT_UNKNOWN_CA:/* 1048 */
    case SSL_R_TLSV1_ALERT_ACCESS_DENIED:/* 1049 */
    case SSL_R_TLSV1_ALERT_DECODE_ERROR:/* 1050 */
    case SSL_R_TLSV1_ALERT_DECRYPT_ERROR:/* 1051 */
    case SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION:/* 1060 */
    case SSL_R_TLSV1_ALERT_PROTOCOL_VERSION:/* 1070 */
    case SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY:/* 1071 */
    case SSL_R_TLSV1_ALERT_INTERNAL_ERROR:/* 1080 */
    case SSL_R_TLSV1_ALERT_USER_CANCELLED:/* 1090 */
    case SSL_R_TLSV1_ALERT_NO_RENEGOTIATION: /* 1100 */
        level = SW_LOG_WARNING;
        break;
#endif

    swoole_error_log(level,
                     SW_ERROR_SSL_BAD_PROTOCOL,
                     "SSL connection#%d[%s:%d] protocol error[%d]",
                     fd,
                     info.get_ip(),
                     info.get_port(),
                     reason);
}

ssize_t Socket::ssl_recv(void *__buf, size_t __n) {
    ssl_clear_error();

    int n = SSL_read(ssl, __buf, __n);
    if (n < 0) {
        int _errno = SSL_get_error(ssl, n);
        switch (_errno) {
        case SSL_ERROR_WANT_READ:
            ssl_want_read = 1;
            errno = EAGAIN;
            return SW_ERR;

        case SSL_ERROR_WANT_WRITE:
            ssl_want_write = 1;
            errno = EAGAIN;
            return SW_ERR;

        case SSL_ERROR_SYSCALL:
            errno = SW_ERROR_SSL_RESET;
            return SW_ERR;

        case SSL_ERROR_SSL:
            ssl_catch_error();
            errno = SW_ERROR_SSL_BAD_CLIENT;
            return SW_ERR;

        default:
            break;
        }
    }
    return n;
}

ssize_t Socket::ssl_send(const void *__buf, size_t __n) {
    ssl_clear_error();

#ifdef SW_SUPPORT_DTLS
    if (dtls && chunk_size && __n > chunk_size) {
        __n = chunk_size;
    }
#endif

    int n = SSL_write(ssl, __buf, __n);
    if (n < 0) {
        int _errno = SSL_get_error(ssl, n);
        switch (_errno) {
        case SSL_ERROR_WANT_READ:
            ssl_want_read = 1;
            errno = EAGAIN;
            return SW_ERR;

        case SSL_ERROR_WANT_WRITE:
            ssl_want_write = 1;
            errno = EAGAIN;
            return SW_ERR;

        case SSL_ERROR_SYSCALL:
            errno = SW_ERROR_SSL_RESET;
            return SW_ERR;

        case SSL_ERROR_SSL:
            ssl_catch_error();
            errno = SW_ERROR_SSL_BAD_CLIENT;
            return SW_ERR;

        default:
            break;
        }
    }
    return n;
}

ssize_t Socket::ssl_readv(IOVector *io_vector) {
    ssize_t retval, total_bytes = 0;

    do {
        retval = ssl_recv(io_vector->get_iterator()->iov_base, io_vector->get_iterator()->iov_len);
        total_bytes += retval > 0 ? retval : 0;
        io_vector->update_iterator(retval);
    } while (retval > 0 && io_vector->get_remain_count() > 0);

    return total_bytes > 0 ? total_bytes : retval;
}

ssize_t Socket::ssl_writev(IOVector *io_vector) {
    ssize_t retval, total_bytes = 0;

    do {
        retval = ssl_send(io_vector->get_iterator()->iov_base, io_vector->get_iterator()->iov_len);
        total_bytes += retval > 0 ? retval : 0;
        io_vector->update_iterator(retval);
    } while (retval > 0 && io_vector->get_remain_count() > 0);

    return total_bytes > 0 ? total_bytes : retval;
}

int Socket::ssl_create(SSLContext *ssl_context, int _flags) {
    ssl_clear_error();

    ssl = SSL_new(ssl_context->get_context());
    if (ssl == nullptr) {
        swoole_warning("SSL_new() failed");
        return SW_ERR;
    }
    if (!SSL_set_fd(ssl, fd)) {
        long err = ERR_get_error();
        swoole_warning("SSL_set_fd() failed. Error: %s[%ld]", ERR_reason_error_string(err), err);
        return SW_ERR;
    }
    if (_flags & SW_SSL_CLIENT) {
        SSL_set_connect_state(ssl);
    } else if (_flags & SW_SSL_SERVER) {
        SSL_set_accept_state(ssl);
    }
    if (SSL_set_ex_data(ssl, swoole_ssl_get_ex_connection_index(), this) == 0) {
        swoole_warning("SSL_set_ex_data() failed");
        return SW_ERR;
    }

#ifdef OPENSSL_IS_BORINGSSL
    SSL_set_enable_ech_grease(ssl, ssl_context->grease);
#endif

    ssl_state = 0;
    return SW_OK;
}

#endif

}  // namespace network

using network::Socket;

Socket *make_socket(SocketType type, FdType fd_type, int flags) {
    int sock_domain;
    int sock_type;

    if (Socket::get_domain_and_type(type, &sock_domain, &sock_type) < 0) {
        swoole_warning("unknown socket type [%d]", type);
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
        if (!network::_fcntl_set_option(sockfd, nonblock ? 1 : -1, cloexec ? 1 : -1)) {
            close(sockfd);
            return nullptr;
        }
    }
#endif
    auto _socket = swoole::make_socket(sockfd, fd_type);
    _socket->nonblock = nonblock;
    _socket->cloexec = cloexec;
    _socket->socket_type = type;
    return _socket;
}

Socket *make_server_socket(SocketType type, const char *address, int port, int backlog) {
    Socket *sock = swoole::make_socket(type, SW_FD_STREAM_SERVER, SW_SOCK_CLOEXEC);
    if (sock == nullptr) {
        swoole_sys_warning("socket() failed");
        return nullptr;
    }
    if (sock->bind(address, &port) < 0) {
        sock->free();
        return nullptr;
    }
    if (sock->is_stream() && sock->listen(backlog) < 0) {
        swoole_sys_warning("listen(%s:%d, %d) failed", address, port, backlog);
        sock->free();
        return nullptr;
    }
    return sock;
}

Socket *make_socket(int fd, FdType fd_type) {
    Socket *socket = new Socket();
    socket->fd = fd;
    socket->fd_type = fd_type;
    socket->removed = 1;
    return socket;
}

}  // namespace swoole
