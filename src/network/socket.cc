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

void IOVector::update_iterator(ssize_t _n) {
    size_t total_bytes = 0;
    size_t _offset_bytes = 0;
    int _index = 0;

    if (_n <= 0 || remain_count == 0) {
        return;
    }

    SW_LOOP_N(remain_count) {
        total_bytes += iov_iterator[i].iov_len;
        if (static_cast<ssize_t>(total_bytes) >= _n) {
            _offset_bytes = iov_iterator[i].iov_len - (total_bytes - _n);
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
            iov_iterator->iov_base = static_cast<char *>(iov_iterator->iov_base) + _offset_bytes;
            iov_iterator->iov_len = iov_iterator->iov_len - _offset_bytes;

            return;
        }
    }

    // represents the length of __n greater than total_bytes
    abort();
}

static bool check_sendfile_parameters(File *file, off_t begin, size_t length, off_t *end) {
    auto filename = file->get_path().c_str();
    if (!file->ready()) {
        swoole_sys_warning("open('%s') failed", filename);
        return false;
    }

    FileStatus file_stat;
    if (!file->stat(&file_stat)) {
        swoole_sys_warning("fstat('%s') failed", filename);
        return false;
    }

    if (file_stat.st_size == 0) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_FILE_EMPTY, "cannot send empty file '%s'", filename);
        return false;
    }

    if (length == 0) {
        *end = file_stat.st_size;
    } else {
        *end = begin + static_cast<off_t>(length);
    }

    if (begin < 0 || *end > file_stat.st_size) {
        swoole_error_log(
            SW_LOG_WARNING, SW_ERROR_INVALID_PARAMS, "length[%ld] or offset[%ld] is invalid", length, (long) begin);
        return false;
    }

    return true;
}

static size_t get_sendfile_chunk_size(off_t begin, off_t end) {
    size_t real_length = end - begin;
    return real_length > SW_SENDFILE_CHUNK_SIZE ? SW_SENDFILE_CHUNK_SIZE : real_length;
}

int Socket::sendfile_sync(const char *filename, off_t offset, size_t length, double timeout) {
    int timeout_ms = timeout < 0 ? -1 : timeout * 1000;
    off_t end;
    File file(filename, O_RDONLY);

    if (!check_sendfile_parameters(&file, offset, length, &end)) {
        return SW_ERR;
    }

    auto corked = false;
    if (end - offset > SW_SOCKET_CORK_MIN_SIZE) {
        corked = cork();
    }

    while (offset < end) {
        size_t sent_bytes = get_sendfile_chunk_size(offset, end);
        ssize_t n = sendfile(file, &offset, sent_bytes);
        if (n <= 0) {
#ifdef SW_USE_OPENSSL
            int event = ssl_want_read ? SW_EVENT_READ : SW_EVENT_WRITE;
#else
            int event = SW_EVENT_WRITE;
#endif
            if (errno == EAGAIN && wait_event(timeout_ms, event) < 0) {
                return SW_ERR;
            }
            swoole_sys_warning("sendfile(%d, %s) failed", fd, filename);
            return SW_ERR;
        }
    }

    if (corked) {
        uncork();
    }

    return SW_OK;
}

ssize_t Socket::writev_sync(const struct iovec *iov, size_t iovcnt) {
    while (true) {
        ssize_t n = writev(iov, iovcnt);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (catch_write_error(errno) == SW_WAIT &&
                wait_event(static_cast<int>(send_timeout_ * 1000), SW_EVENT_WRITE) == SW_OK) {
                continue;
            }
            swoole_sys_warning("send %lu bytes failed", iov[1].iov_len);
            return SW_ERR;
        }
        return n;
    }
    return -1;
}

int Socket::connect_sync(const Address &sa, double timeout) {
    set_nonblock();
    auto ret = connect(sa);
    if (ret != -1) {
        return SW_OK;
    }
    if (errno != EINPROGRESS) {
        swoole_set_last_error(errno);
        return SW_ERR;
    }
    if (wait_event(timeout > 0 ? (int) (timeout * 1000) : timeout, SW_EVENT_WRITE) < 0) {
        swoole_set_last_error(ETIMEDOUT);
        return SW_ERR;
    }
    int err;
    socklen_t len = sizeof(len);
    ret = get_option(SOL_SOCKET, SO_ERROR, &err, &len);
    if (ret < 0) {
        swoole_set_last_error(errno);
        return SW_ERR;
    }
    if (err != 0) {
        swoole_set_last_error(err);
        return SW_ERR;
    }
    set_block();
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
    pollfd event;
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
    while (true) {
        int ret = poll(&event, 1, timeout_ms);
        if (ret == 0) {
            swoole_set_last_error(SW_ERROR_SOCKET_POLL_TIMEOUT);
            return SW_ERR;
        }
        if (ret < 0) {
            if (errno != EINTR) {
                swoole_sys_warning("poll() failed");
                return SW_ERR;
            }
            if (dont_restart) {
                return SW_ERR;
            }
            continue;
        }
        return SW_OK;
    }
    return SW_OK;
}

ssize_t Socket::send_sync(const void *_data, size_t _len) {
    ssize_t n = 0;
    ssize_t written = 0;

    while (written < static_cast<ssize_t>(_len)) {
#ifdef SW_USE_OPENSSL
        if (ssl) {
            n = ssl_send((char *) _data + written, _len - written);
        } else
#endif
        {
            n = ::send(fd, (char *) _data + written, _len - written, 0);
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            } else if (catch_write_error(errno) == SW_WAIT &&
                       wait_event((int) (send_timeout_ * 1000), SW_EVENT_WRITE) == SW_OK) {
                continue;
            } else {
                swoole_sys_warning("send %lu bytes failed", _len);
                return SW_ERR;
            }
        }
        written += n;
    }

    return written;
}

ssize_t Socket::recv_sync(void *_data, size_t _len, int flags) {
    size_t read_bytes = 0;

    while (read_bytes != _len) {
        ssize_t ret = ::recv(fd, static_cast<char *>(_data) + read_bytes, _len - read_bytes, flags);
        if (ret > 0) {
            read_bytes += ret;
        } else if (ret == 0) {
            return read_bytes;
        } else if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (catch_read_error(errno) == SW_WAIT &&
                wait_event(static_cast<int>(recv_timeout_ * 1000), SW_EVENT_READ) == SW_OK) {
                continue;
            }
            return ret;
        }
    }

    return read_bytes;
}

Socket *Socket::accept() {
    auto *socket = new Socket();
    socket->removed = 1;
    socket->socket_type = socket_type;
    socket->info.len = sizeof(socket->info);
#ifdef HAVE_ACCEPT4
    int flags = SOCK_CLOEXEC;
    if (nonblock) {
        flags |= SOCK_NONBLOCK;
    }
    socket->fd = ::accept4(fd, reinterpret_cast<sockaddr *>(&socket->info.addr), &socket->info.len, flags);
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

ssize_t Socket::sendto_sync(const Address &sa, const void *_buf, size_t _n, int flags) {
    ssize_t n = 0;

    SW_LOOP_N(SW_SOCKET_RETRY_COUNT) {
        n = sendto(sa, _buf, _n, flags);
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

ssize_t Socket::recvfrom(char *buf, size_t len, int flags, sockaddr *addr, socklen_t *addr_len) {
    ssize_t n = 0;
    SW_LOOP_N(SW_SOCKET_RETRY_COUNT) {
        n = ::recvfrom(fd, buf, len, flags, addr, addr_len);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    return n;
}

ssize_t Socket::recvfrom_sync(char *buf, size_t len, int flags, Address *sa) {
    return recvfrom_sync(buf, len, flags, &sa->addr.ss, &sa->len);
}

ssize_t Socket::recvfrom_sync(char *buf, size_t len, int flags, sockaddr *addr, socklen_t *addr_len) {
    ssize_t n = 0;
    SW_LOOP_N(SW_SOCKET_RETRY_COUNT) {
        n = recvfrom(buf, len, flags, addr, addr_len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (catch_read_error(errno) == SW_WAIT &&
                wait_event((int) (recv_timeout_ * 1000), SW_EVENT_READ) == SW_OK) {
                continue;
            }
        }
        break;
    }
    return n;
}

static void socket_free_defer(void *ptr) {
    auto *sock = static_cast<Socket *>(ptr);
    if (sock->is_local() && sock->bound) {
        ::unlink(sock->get_addr());
    }
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

    delete in_buffer;
    delete out_buffer;

    if (swoole_event_is_available()) {
        removed = 1;
        swoole_event_defer(socket_free_defer, this);
    } else {
        socket_free_defer(this);
    }
}

int Socket::get_name() {
    info.len = sizeof(info.addr);
    if (getsockname(fd, &info.addr.ss, &info.len) < 0) {
        return -1;
    }
    info.type = socket_type;
    return 0;
}

int Socket::get_peer_name(Address *sa) {
    sa->len = sizeof(sa->addr);
    sa->type = socket_type;
    if (::getpeername(fd, &sa->addr.ss, &sa->len) != 0) {
        return SW_ERR;
    }
    return SW_OK;
}

int Socket::set_tcp_nopush(int nopush) {
#ifdef TCP_CORK
    if (set_option(IPPROTO_TCP, TCP_CORK, nopush) == SW_ERR) {
        return -1;
    } else {
        tcp_nopush = nopush;
        return 0;
    }
#else
    return -1;
#endif
}

int Socket::bind(const std::string &_host, int port) {
    Address addr;
    if (!addr.assign(socket_type, _host, port, false)) {
        return SW_ERR;
    }
    return bind(addr);
}

int Socket::bind(const struct sockaddr *sa, socklen_t len) {
    if (::bind(fd, sa, len) < 0) {
        return SW_ERR;
    }
    bound = 1;
    return SW_OK;
}

int Socket::listen(int backlog) {
    if (::listen(fd, backlog <= 0 ? SW_BACKLOG : backlog) < 0) {
        return SW_ERR;
    }
    listened = 1;
    return SW_OK;
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
        swoole_sys_warning("setsockopt(%d, SOL_SOCKET, SO_RCVBUF, %d) failed", fd, _buffer_size);
        return false;
    }
    return true;
}

bool Socket::set_send_buffer_size(uint32_t _buffer_size) {
    if (set_option(SOL_SOCKET, SO_SNDBUF, _buffer_size) != 0) {
        swoole_sys_warning("setsockopt(%d, SOL_SOCKET, SO_SNDBUF, %d) failed", fd, _buffer_size);
        return false;
    }
    return true;
}

bool Socket::set_timeout(double timeout) {
    return set_recv_timeout(timeout) and set_send_timeout(timeout);
}

bool Socket::check_liveness() {
    char buf;
    errno = 0;
    ssize_t retval = peek(&buf, sizeof(buf), MSG_DONTWAIT);
    return !(retval == 0 || (retval < 0 && catch_read_error(errno) == SW_CLOSE));
}

bool Socket::set_tcp_nodelay(int nodelay) {
    if (set_option(IPPROTO_TCP, TCP_NODELAY, nodelay) == SW_ERR) {
        return false;
    } else {
        tcp_nodelay = nodelay;
        return true;
    }
}

bool Socket::cork() {
    if (tcp_nopush) {
        return false;
    }
#ifdef TCP_CORK
    if (set_tcp_nopush(1) < 0) {
        swoole_sys_warning("set_tcp_nopush(fd=%d, ON) failed", fd);
        return false;
    }
#endif
    // Need to turn off tcp nodelay when using nopush
    if (tcp_nodelay && !set_tcp_nodelay(0)) {
        swoole_sys_warning("set_tcp_nodelay(fd=%d, OFF) failed", fd);
    }
    return true;
}

bool Socket::uncork() {
    if (!tcp_nopush) {
        return false;
    }
#ifdef TCP_CORK
    if (set_tcp_nopush(0) < 0) {
        swoole_sys_warning("set_tcp_nopush(fd=%d, OFF) failed", fd);
        return false;
    }
#endif
    // Restore tcp_nodelay setting
    if (enable_tcp_nodelay && tcp_nodelay == 0 && !set_tcp_nodelay(1)) {
        swoole_sys_warning("set_tcp_nodelay(fd=%d, ON) failed", fd);
        return false;
    }
    return true;
}

Socket *Socket::dup() {
    auto *_socket = new Socket();
    *_socket = *this;
    _socket->fd = ::dup(fd);
    return _socket;
}

static bool _set_timeout(int fd, int type, double timeout) {
    struct timeval timeo;
    timeo.tv_sec = (int) timeout;
    timeo.tv_usec = (int) ((timeout - timeo.tv_sec) * 1000 * 1000);
    int ret = setsockopt(fd, SOL_SOCKET, type, (void *) &timeo, sizeof(timeo));
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
    Buffer *buffer = out_buffer;
    BufferChunk *chunk = buffer->front();
    auto *task = (SendfileRequest *) chunk->value.ptr;

    if (task->corked == 0) {
        if (task->end - task->begin > SW_SOCKET_CORK_MIN_SIZE) {
            task->corked = cork() ? 1 : -1;
        } else {
            task->corked = -1;
        }
    }

    size_t sendn = get_sendfile_chunk_size(task->begin, task->end);
    ssize_t rv = sendfile(task->file, &task->begin, sendn);

    swoole_trace("rv=%ld|begin=%ld|sendn=%lu|end=%lu", rv, (long) task->begin, sendn, task->end);

    if (rv <= 0) {
        switch (catch_write_error(errno)) {
        case SW_ERROR:
            swoole_sys_warning("sendfile(%s, %ld, %zu) failed", task->get_filename(), (long) task->begin, sendn);
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
    if (task->begin == task->end) {
        if (task->corked == 1) {
            uncork();
            task->corked = 0;
        }
        buffer->pop();
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

    ssize_t ret = send(chunk->value.str + chunk->offset, sendn, 0);
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
    auto *task = static_cast<SendfileRequest *>(chunk->value.ptr);
    delete task;
}

ssize_t Socket::sendfile(const File &fp, off_t *offset, size_t length) {
#ifdef SW_USE_OPENSSL
    if (ssl) {
        return ssl_sendfile(fp, offset, length);
    } else
#endif
    {
        return ::swoole_sendfile(fd, fp.get_fd(), offset, length);
    }
}

int Socket::sendfile_async(const char *filename, off_t offset, size_t length) {
    std::unique_ptr<SendfileRequest> task(new SendfileRequest(filename, offset));

    if (!check_sendfile_parameters(&task->file, offset, length, &task->end)) {
        return SW_ERR;
    }

    if (out_buffer == nullptr) {
        out_buffer = new Buffer(SW_SEND_BUFFER_SIZE);
    }

    BufferChunk *chunk = out_buffer->alloc(BufferChunk::TYPE_SENDFILE, 0);
    chunk->value.ptr = task.release();
    chunk->destroy = Socket_sendfile_destructor;

    return SW_OK;
}

ssize_t Socket::recv(void *_buf, size_t _n, int _flags) {
    ssize_t total_bytes = 0;

    do {
#ifdef SW_USE_OPENSSL
        if (ssl) {
            ssize_t retval = 0;
            while (static_cast<size_t>(total_bytes) < _n) {
                retval = ssl_recv(static_cast<char *>(_buf) + total_bytes, _n - total_bytes);
                if (retval <= 0) {
                    if (total_bytes == 0) {
                        total_bytes = retval;
                    }
                    break;
                } else {
                    total_bytes += retval;
                    if (!(nonblock || (_flags & MSG_WAITALL))) {
                        break;
                    }
                }
            }
        } else
#endif
        {
            total_bytes = ::recv(fd, _buf, _n, _flags);
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

    swoole_trace_log(SW_TRACE_SOCKET, "recv %ld/%ld bytes, errno=%d", total_bytes, _n, errno);

    return total_bytes;
}

ssize_t Socket::send(const void *_buf, size_t _n, int _flags) {
    ssize_t retval;

    do {
#ifdef SW_USE_OPENSSL
        if (ssl) {
            retval = ssl_send(_buf, _n);
        } else
#endif
        {
            retval = ::send(fd, _buf, _n, _flags);
        }
    } while (retval < 0 && errno == EINTR);

    if (retval > 0) {
        total_send_bytes += retval;
        if (send_timer) {
            last_sent_time = time<std::chrono::milliseconds>(true);
        }
    }

    swoole_trace_log(SW_TRACE_SOCKET, "send %ld/%ld bytes, errno=%d", retval, _n, errno);

    return retval;
}

ssize_t Socket::send_async(const void *_buf, size_t _n) {
    if (!swoole_event_is_available()) {
        return send_sync(_buf, _n);
    } else {
        return swoole_event_write(this, _buf, _n);
    }
}

ssize_t Socket::read_sync(void *_buf, size_t _len, int timeout_ms) {
    struct pollfd event;
    event.fd = fd;
    event.events = POLLIN;
    if (poll(&event, 1, timeout_ms) == 1) {
        return read(_buf, _len);
    } else {
        return -1;
    }
}

ssize_t Socket::write_sync(const void *_buf, size_t _len, int timeout_ms) {
    struct pollfd event;
    event.fd = fd;
    event.events = POLLOUT;
    if (poll(&event, 1, timeout_ms) == 1) {
        return write(_buf, _len);
    } else {
        return -1;
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

ssize_t Socket::peek(void *_buf, size_t _n, int _flags) {
    ssize_t retval;
    _flags |= MSG_PEEK;
    do {
#ifdef SW_USE_OPENSSL
        if (ssl) {
            retval = SSL_peek(ssl, _buf, _n);
        } else
#endif
        {
            retval = ::recv(fd, _buf, _n, _flags);
        }
    } while (retval < 0 && errno == EINTR);

    swoole_trace_log(SW_TRACE_SOCKET, "peek %ld/%ld bytes, errno=%d", retval, _n, errno);

    return retval;
}

int Socket::catch_error(int err) const {
    switch (err) {
    case EFAULT:
        abort();
        return SW_ERROR;
    case EBADF:
    case ENOENT:
        return SW_INVALID;
    case ECONNRESET:
    case ECONNABORTED:
    case EPIPE:
    case ENOTCONN:
    case ETIMEDOUT:
    case ECONNREFUSED:
    case ENETDOWN:
    case ENETUNREACH:
    case EHOSTDOWN:
    case EHOSTUNREACH:
    case SW_ERROR_SSL_BAD_CLIENT:
    case SW_ERROR_SSL_RESET:
        return SW_CLOSE;
    case EAGAIN:
#if EAGAIN != EWOULDBLOCK
    case EWOULDBLOCK:
#endif
#ifdef HAVE_KQUEUE
    case ENOBUFS:
#endif
    case 0:
        return SW_WAIT;
    default:
        return SW_ERROR;
    }
}

SocketType Socket::convert_to_type(int domain, int type) {
    if (domain == AF_INET && type == SOCK_STREAM) {
        return SW_SOCK_TCP;
    } else if (domain == AF_INET6 && type == SOCK_STREAM) {
        return SW_SOCK_TCP6;
    } else if (domain == AF_UNIX && type == SOCK_STREAM) {
        return SW_SOCK_UNIX_STREAM;
    } else if (domain == AF_INET && type == SOCK_DGRAM) {
        return SW_SOCK_UDP;
    } else if (domain == AF_INET6 && type == SOCK_DGRAM) {
        return SW_SOCK_UDP6;
    } else if (domain == AF_UNIX && type == SOCK_DGRAM) {
        return SW_SOCK_UNIX_DGRAM;
    } else if (domain == AF_INET && type == SOCK_RAW) {
        return SW_SOCK_RAW;
    } else if (domain == AF_INET6 && type == SOCK_RAW) {
        return SW_SOCK_RAW6;
    } else {
        return SW_SOCK_RAW;
    }
}

SocketType Socket::convert_to_type(std::string &host) {
    if (host.compare(0, 6, "unix:/", 0, 6) == 0) {
        host = host.substr(sizeof("unix:") - 1);
        host.erase(0, host.find_first_not_of('/') - 1);
        return SW_SOCK_UNIX_STREAM;
    }
    if (host.find(':') != std::string::npos) {
        return SW_SOCK_TCP6;
    }
    return SW_SOCK_TCP;
}

int Socket::get_domain_and_type(SocketType type, int *sock_domain, int *sock_type) {
    switch (type) {
    case SW_SOCK_TCP6:
        *sock_domain = AF_INET6;
        *sock_type = SOCK_STREAM;
        break;
    case SW_SOCK_UNIX_STREAM:
        *sock_domain = AF_UNIX;
        *sock_type = SOCK_STREAM;
        break;
    case SW_SOCK_UDP:
        *sock_domain = AF_INET;
        *sock_type = SOCK_DGRAM;
        break;
    case SW_SOCK_UDP6:
        *sock_domain = AF_INET6;
        *sock_type = SOCK_DGRAM;
        break;
    case SW_SOCK_UNIX_DGRAM:
        *sock_domain = AF_UNIX;
        *sock_type = SOCK_DGRAM;
        break;
    case SW_SOCK_TCP:
        *sock_domain = AF_INET;
        *sock_type = SOCK_STREAM;
        break;
    case SW_SOCK_RAW:
        *sock_domain = AF_INET;
        *sock_type = SOCK_RAW;
        break;
    case SW_SOCK_RAW6:
        *sock_domain = AF_INET6;
        *sock_type = SOCK_RAW;
        break;
    default:
        return SW_ERR;
    }

    return SW_OK;
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
        return nullptr;
    }
    return SSL_get_peer_certificate(ssl);
}

STACK_OF(X509) * Socket::ssl_get_peer_cert_chain() {
    if (!ssl) {
        return nullptr;
    }
    return SSL_get_peer_cert_chain(ssl);
}

static int _ssl_read_x509_file(X509 *cert, char *buffer, size_t length) {
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

    int len = BIO_pending(bio);
    if (len < 0 && len > static_cast<int>(length)) {
        swoole_warning("certificate length[%d] is too big", len);
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
        auto rv = _ssl_read_x509_file(cert, sw_tg_buffer()->str, sw_tg_buffer()->size);
        if (rv > 0) {
            list.emplace_back(sw_tg_buffer()->str, rv);
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
    ulong_t error = ERR_get_error();
    if (reason) {
        *reason = ERR_GET_REASON(error);
    }
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
                       info.get_addr(),
                       info.get_port(),
                       reason,
                       error_string);
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

    ulong_t err_code = ERR_get_error();
    char *msg = ERR_error_string(err_code, sw_tg_buffer()->str);
    swoole_notice("Socket::ssl_connect(fd=%d) to server[%s:%d] failed. Error: %s[%ld|%d]",
                  fd,
                  info.get_addr(),
                  info.get_port(),
                  msg,
                  err,
                  ERR_GET_REASON(err_code));

    return SW_ERR;
}

ssize_t Socket::ssl_sendfile(const File &fp, off_t *_offset, size_t _size) {
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
                     info.get_addr(),
                     info.get_port(),
                     reason);
}

ssize_t Socket::ssl_recv(void *_buf, size_t _n) {
    ssl_clear_error();

    int n = SSL_read(ssl, _buf, _n);
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
            return errno == 0 ? 0 : SW_ERR;

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

ssize_t Socket::ssl_send(const void *_buf, size_t _n) {
    ssl_clear_error();

#ifdef SW_SUPPORT_DTLS
    if (dtls && chunk_size && _n > chunk_size) {
        _n = chunk_size;
    }
#endif

    int n = SSL_write(ssl, _buf, _n);
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
        ulong_t err = ERR_get_error();
        swoole_warning("SSL_set_fd() failed. Error: %s[%lu]", ERR_reason_error_string(err), err);
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
        swoole_set_last_error(errno);
        return nullptr;
    }

    return make_socket(type, fd_type, sock_domain, sock_type, 0, flags);
}

Socket *make_socket(SocketType type, FdType fd_type, int sock_domain, int sock_type, int socket_protocol, int flags) {
    int sockfd = swoole::socket(sock_domain, sock_type, socket_protocol, flags);
    if (sockfd < 0) {
        swoole_set_last_error(errno);
        return nullptr;
    }

    auto _socket = make_socket(sockfd, fd_type);
    _socket->nonblock = !!(flags & SW_SOCK_NONBLOCK);
    _socket->cloexec = !!(flags & SW_SOCK_CLOEXEC);
    _socket->socket_type = type;
    return _socket;
}

int socket(int sock_domain, int sock_type, int socket_protocol, int flags) {
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
    int sockfd = ::socket(sock_domain, sock_type | sock_flags, socket_protocol);
    if (sockfd < 0) {
        return sockfd;
    }
#else
    int sockfd = ::socket(sock_domain, sock_type, socket_protocol);
    if (sockfd < 0) {
        return sockfd;
    }
    if (nonblock || cloexec) {
        if (!network::_fcntl_set_option(sockfd, nonblock ? 1 : -1, cloexec ? 1 : -1)) {
            close(sockfd);
            return sockfd;
        }
    }
#endif
    return sockfd;
}

Socket *make_server_socket(SocketType type, const char *address, int port, int backlog) {
    Socket *sock = swoole::make_socket(type, SW_FD_STREAM_SERVER, SW_SOCK_CLOEXEC);
    if (sock == nullptr) {
        swoole_sys_warning("socket() failed");
        return nullptr;
    }
    if (sock->bind(address, port) < 0) {
        swoole_sys_warning("bind(%d, %s:%d, %d) failed", sock->get_fd(), address, port, backlog);
        goto __cleanup;
    }
    if (sock->is_stream() && sock->listen(backlog) < 0) {
        swoole_sys_warning("listen(%d, %s:%d, %d) failed", sock->get_fd(), address, port, backlog);
        goto __cleanup;
    }
    if (sock->get_name() < 0) {
        swoole_sys_warning("getsockname(%d) failed", sock->get_fd());
    __cleanup:
        sock->free();
        return nullptr;
    }
    return sock;
}

Socket *make_socket(int fd, FdType fd_type) {
    auto *socket = new Socket();
    socket->fd = fd;
    socket->fd_type = fd_type;
    socket->removed = 1;
    return socket;
}

}  // namespace swoole
