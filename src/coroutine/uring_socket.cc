

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
  | @link     https://www.swoole.com/                                    |
  | @contact  team@swoole.com                                            |
  | @license  https://github.com/swoole/swoole-src/blob/master/LICENSE   |
  | @Author   Tianfeng Han  <rango@swoole.com>                           |
  +----------------------------------------------------------------------+
*/

#include "swoole_uring_socket.h"
#include "swoole_coroutine_socket.h"
#include "swoole_coroutine_system.h"
#include "swoole_util.h"
#include "swoole_iouring.h"

typedef swoole::network::Socket NetSocket;

#ifdef SW_USE_IOURING
namespace swoole {
namespace coroutine {
bool UringSocket::connect(const sockaddr *addr, socklen_t addrlen) {
    if (sw_unlikely(!is_available(SW_EVENT_RDWR))) {
        return false;
    }

    write_co = read_co = Coroutine::get_current_safe();
    int retval = Iouring::connect(socket->get_fd(), addr, addrlen, socket->connect_timeout);
    write_co = read_co = nullptr;
    if (retval < 0) {
        return false;
    }

    connected = true;
    socket->get_name();
    set_err(0);
    return true;
}

UringSocket *UringSocket::accept(double timeout) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return nullptr;
    }
    if (ssl_is_enable() && sw_unlikely(ssl_context->context == nullptr) && !ssl_context_create()) {
        return nullptr;
    }

    read_co = Coroutine::get_current_safe();
    network::Socket *conn = uring_accept(timeout == 0 ? socket->read_timeout : timeout);
    read_co = nullptr;

    if (conn == nullptr) {
        set_err(errno);
        return nullptr;
    }

    auto *client_sock = new UringSocket(conn, this);
    if (sw_unlikely(client_sock->get_fd() < 0)) {
        swoole_sys_warning("new Socket() failed");
        set_err(errno);
        delete client_sock;
        return nullptr;
    }

    return client_sock;
}

NetSocket *UringSocket::uring_accept(double timeout) {
    auto *client_socket = new NetSocket();
    int fd = Iouring::accept(socket->get_fd(),
                             reinterpret_cast<sockaddr *>(&client_socket->info.addr),
                             &client_socket->info.len,
                             SOCK_CLOEXEC | SOCK_NONBLOCK,
                             socket->read_timeout);
    if (fd < 0) {
        delete client_socket;
        return nullptr;
    }

    client_socket->fd = fd;
    client_socket->removed = 1;
    client_socket->info.type = socket->socket_type;
    client_socket->nonblock = 1;
    client_socket->cloexec = 1;

    return client_socket;
}

ssize_t UringSocket::uring_send(const void *_buf, size_t _n) {
    return Iouring::send(socket->get_fd(), _buf, _n, 0, socket->write_timeout);
}

ssize_t UringSocket::uring_recv(void *_buf, size_t _n) {
    return Iouring::recv(socket->get_fd(), _buf, _n, 0, socket->read_timeout);
}

ssize_t UringSocket::uring_readv(const struct iovec *iovec, int count) {
    return Iouring::readv(socket->get_fd(), iovec, count, socket->read_timeout);
}

ssize_t UringSocket::uring_writev(const struct iovec *iovec, int count) {
    return Iouring::writev(socket->get_fd(), iovec, count, socket->write_timeout);
}

ssize_t UringSocket::uring_sendfile(const File &file, off_t *offset, size_t size) {
    return Iouring::sendfile(socket->get_fd(), file.get_fd(), offset, size, socket->write_timeout);
}

ssize_t UringSocket::read(void *_buf, size_t _n) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    read_co = Coroutine::get_current_safe();
    ssize_t retval = Iouring::read(socket->get_fd(), _buf, _n, socket->read_timeout);
    read_co = nullptr;
    check_return_value(retval);
    return retval;
}

ssize_t UringSocket::write(const void *_buf, size_t _n) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }
    write_co = Coroutine::get_current_safe();
    ssize_t retval = Iouring::write(socket->get_fd(), _buf, _n, socket->write_timeout);
    write_co = nullptr;
    check_return_value(retval);
    return retval;
}

ssize_t UringSocket::recvmsg(msghdr *msg, int flags) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    read_co = Coroutine::get_current_safe();
    ssize_t retval = Iouring::recvmsg(socket->get_fd(), msg, flags, socket->read_timeout);
    read_co = nullptr;
    check_return_value(retval);
    return retval;
}

ssize_t UringSocket::sendmsg(const msghdr *msg, int flags) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }
    write_co = Coroutine::get_current_safe();
    ssize_t retval = Iouring::sendmsg(socket->get_fd(), msg, flags, socket->write_timeout);
    write_co = nullptr;
    check_return_value(retval);
    return retval;
}

ssize_t UringSocket::recvfrom(void *_buf, size_t _n, sockaddr *_addr, socklen_t *_socklen) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    read_co = Coroutine::get_current_safe();
    ssize_t retval = Iouring::recvfrom(socket->get_fd(), _buf, _n, _addr, _socklen, socket->read_timeout);
    read_co = nullptr;
    check_return_value(retval);
    return retval;
}

ssize_t UringSocket::sendto(const std::string &host, int port, const void *_buf, size_t _n) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }

    ssize_t retval = 0;
    network::Address addr;

    if (!socket->is_dgram()) {
        set_err(EPROTONOSUPPORT);
        return -1;
    }

    auto ip_addr = host;

    SW_LOOP_N(2) {
        if (!addr.assign(type, ip_addr, port, false)) {
            if (swoole_get_last_error() == SW_ERROR_BAD_HOST_ADDR) {
                ip_addr = System::gethostbyname(host, sock_domain, socket->dns_timeout);
                if (!ip_addr.empty()) {
                    continue;
                }
            }
            set_err();
            return -1;
        }
        break;
    }

    write_co = Coroutine::get_current_safe();
    retval = Iouring::sendto(socket->get_fd(), _buf, _n, 0, &addr.addr.ss, addr.len, socket->write_timeout);
    write_co = nullptr;

    swoole_trace_log(SW_TRACE_SOCKET, "sendto %ld/%ld bytes, errno=%d", retval, _n, errno);

    check_return_value(retval);
    return retval;
}

ssize_t UringSocket::recv(void *_buf, size_t _n) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }

    ssize_t retval;
    read_co = Coroutine::get_current_safe();
    if (is_ssl()) {
        retval = ssl_recv(_buf, _n);
    } else {
        retval = uring_recv(_buf, _n);
    }
    read_co = nullptr;

    check_return_value(retval);
    return retval;
}

ssize_t UringSocket::send(const void *_buf, size_t _n) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }

    ssize_t retval;
    write_co = Coroutine::get_current_safe();
    if (is_ssl()) {
        retval = ssl_send(_buf, _n);
    } else {
        retval = uring_send(_buf, _n);
    }
    write_co = nullptr;

    check_return_value(retval);
    return retval;
}

ssize_t UringSocket::recv_all(void *_buf, size_t _n) {
    ssize_t retval = 0;
    size_t total_bytes = 0;

    do {
        retval = recv((char *) _buf + total_bytes, _n - total_bytes);
        if (retval <= 0) {
            break;
        }
        total_bytes += retval;
    } while (total_bytes < _n);

    check_return_value(retval);
    return retval < 0 && total_bytes == 0 ? -1 : total_bytes;
}

ssize_t UringSocket::send_all(const void *_buf, size_t _n) {
    ssize_t retval = 0;
    size_t total_bytes = 0;

    do {
        retval = send((char *) _buf + total_bytes, _n - total_bytes);
        if (retval <= 0) {
            break;
        }
        total_bytes += retval;
    } while (total_bytes < _n);

    check_return_value(retval);
    return retval < 0 && total_bytes == 0 ? -1 : total_bytes;
}

bool UringSocket::poll(EventType _type, double timeout) {
    if (sw_unlikely(!is_available(_type))) {
        return false;
    }
    struct pollfd fds[1];
    fds[0].events = translate_events_to_poll(_type);
    fds[0].fd = socket->get_fd();
    fds[0].revents = 0;
    return Iouring::poll(fds, 1, timeout * 1000) == 1;
}

bool UringSocket::sendfile(const char *filename, off_t offset, size_t length) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return false;
    }

    File file(filename, O_RDONLY);
    if (!file.ready()) {
        set_err(errno, std_string::format("open(%s) failed, %s", filename, strerror(errno)));
        return false;
    }

    if (length == 0) {
        FileStatus file_stat;
        if (!file.stat(&file_stat)) {
            set_err(errno, std_string::format("fstat(%s) failed, %s", filename, strerror(errno)));
            return false;
        }
        length = file_stat.st_size;
    } else {
        // total length of the file
        length = offset + length;
    }

    ssize_t retval;

    write_co = Coroutine::get_current_safe();
    if (is_ssl()) {
        retval = ssl_sendfile(file, &offset, length);
    } else {
        retval = uring_sendfile(file, &offset, length);
    }
    write_co = nullptr;

    return retval == (ssize_t) length;
}

ssize_t UringSocket::readv(network::IOVector *io_vector) {
    ssize_t retval;
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }

    read_co = Coroutine::get_current_safe();
    do {
        if (is_ssl()) {
            retval = ssl_readv(io_vector);
        } else {
            retval = uring_readv(io_vector->get_iterator(), io_vector->get_remain_count());
        }
        io_vector->update_iterator(retval);
    } while (retval < 0 && errno == EINTR);
    read_co = nullptr;

    check_return_value(retval);
    return retval;
}

ssize_t UringSocket::writev(network::IOVector *io_vector) {
    ssize_t retval;
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }

    write_co = Coroutine::get_current_safe();
    do {
        if (is_ssl()) {
            retval = ssl_writev(io_vector);
        } else {
            retval = uring_writev(io_vector->get_iterator(), io_vector->get_remain_count());
        }
        io_vector->update_iterator(retval);
    } while (retval < 0 && errno == EINTR);
    write_co = nullptr;

    check_return_value(retval);
    return retval;
}

ssize_t UringSocket::readv_all(network::IOVector *io_vector) {
    ssize_t retval = 0;
    size_t total_bytes = 0;

    do {
        retval = readv(io_vector);
        if (retval <= 0) {
            break;
        }
        total_bytes += retval;
    } while (retval > 0 && io_vector->get_remain_count() > 0);

    check_return_value(retval);
    return retval < 0 && total_bytes == 0 ? -1 : total_bytes;
}

ssize_t UringSocket::writev_all(network::IOVector *io_vector) {
    ssize_t retval = 0;
    size_t total_bytes = 0;

    do {
        retval = writev(io_vector);
        if (retval <= 0) {
            break;
        }
        total_bytes += retval;
    } while (retval > 0 && io_vector->get_remain_count() > 0);

    check_return_value(retval);
    return retval < 0 && total_bytes == 0 ? -1 : total_bytes;
}

bool UringSocket::ssl_bio_write() {
    auto buf = get_write_buffer();

    while (true) {
        size_t pending = BIO_ctrl_pending(wbio);
        if (pending == 0) {
            break;
        }

        int nread = BIO_read(wbio, buf->str, buf->size);
        if (nread <= 0) {
            set_err(SW_ERROR_SSL_BAD_PROTOCOL);
            return false;
        }

        ssize_t written = 0;
        while (written < nread) {
            ssize_t n = uring_send(buf->str + written, nread - written);
            if (n > 0) {
                written += n;
            } else if (n == 0) {
                errno = SW_ERROR_SSL_RESET;
                return false;
            } else {
                if (errno == EINTR) {
                    continue;
                }
                set_err(errno);
                return false;
            }
        }
    }

    return true;
}

bool UringSocket::ssl_bio_read() {
    auto buf = get_read_buffer();
    ssize_t rv = uring_recv(buf->str, buf->size);
    if (rv > 0) {
        int written = BIO_write(rbio, buf->str, rv);
        if (written != rv) {
            set_err(SW_ERROR_SSL_BAD_PROTOCOL);
            return false;
        }
        return true;
    } else if (rv == 0) {
        set_err(SW_ERROR_SSL_RESET);
        return false;
    } else {
        if (errno == EINTR) {
            return ssl_bio_read();
        }
        set_err(errno);
        return false;
    }
}

bool UringSocket::ssl_bio_prepare() {
    if (BIO_ctrl_pending(wbio) > 0) {
        if (!ssl_bio_write()) {
            check_return_value(-1);
            return false;
        }
    }
    return true;
}

bool UringSocket::ssl_bio_perform(int rc, const char *fn) {
    if (!ssl_bio_prepare()) {
        return false;
    }

    int error = SSL_get_error(socket->ssl, rc);
    if (error == SSL_ERROR_WANT_WRITE) {
        if (ssl_bio_write()) {
        _error:
            check_return_value(-1);
            return false;
        }
        return true;
    } else if (error == SSL_ERROR_WANT_READ) {
        if (!ssl_bio_read()) {
            goto _error;
        }
        return true;
    } else if (error == SSL_ERROR_ZERO_RETURN) {
        swoole_debug("%s(fd=%d) return zero value", fn, fd);
        error = SW_ERROR_SSL_RESET;
        goto _error;
    } else if (error == SSL_ERROR_SYSCALL) {
        goto _error;
    } else {
        ulong_t err_code = ERR_get_error();
        if (err_code) {
            char error_buf[512];
            ERR_error_string_n(err_code, error_buf, sizeof(error_buf));
            swoole_notice("%s(fd=%d) to server[%s:%d] failed. Error: %s[%d|%d]",
                          fn,
                          socket->get_fd(),
                          socket->info.get_addr(),
                          socket->info.get_port(),
                          error_buf,
                          error,
                          ERR_GET_REASON(err_code));
            set_err(SW_ERROR_SSL_BAD_PROTOCOL, error_buf);
        } else {
            set_err(SW_ERROR_SSL_BAD_PROTOCOL);
        }
        return false;
    }
}

bool UringSocket::ssl_handshake() {
    if (ssl_handshaked) {
        set_err(SW_ERROR_WRONG_OPERATION);
        return false;
    }
    if (sw_unlikely(!is_available(SW_EVENT_RDWR))) {
        return false;
    }

    /**
     * If the ssl_context is empty, it indicates that this socket was not a connection
     * returned by a server socket accept, and a new ssl_context needs to be created.
     */
    if (ssl_context->context == nullptr && !ssl_context_create()) {
        return false;
    }
    if (!ssl_create(get_ssl_context())) {
        return false;
    }
    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(socket->ssl, rbio, wbio);

    const char *fn;
    if (ssl_is_server) {
        fn = "ssl_accept";
        SSL_set_accept_state(socket->ssl);
    } else {
        fn = "ssl_connect";
        SSL_set_connect_state(socket->ssl);
    }

    while (true) {
        auto rs = SSL_do_handshake(socket->ssl);
        if (rs == 1) {
            break;
        }
        if (ssl_bio_perform(rs, fn)) {
            continue;
        } else {
            return false;
        }
    }

    if (ssl_context->verify_peer) {
        if (!ssl_verify(ssl_context->allow_self_signed)) {
            return false;
        }
    }
    ssl_handshaked = true;

    return true;
}

ssize_t UringSocket::ssl_readv(network::IOVector *io_vector) {
    ssize_t retval, total_bytes = 0;

    do {
        retval = ssl_recv(io_vector->get_iterator()->iov_base, io_vector->get_iterator()->iov_len);
        total_bytes += retval > 0 ? retval : 0;
        io_vector->update_iterator(retval);
    } while (retval > 0 && io_vector->get_remain_count() > 0);

    return total_bytes > 0 ? total_bytes : retval;
}

ssize_t UringSocket::ssl_writev(network::IOVector *io_vector) {
    ssize_t retval, total_bytes = 0;

    do {
        retval = ssl_send(io_vector->get_iterator()->iov_base, io_vector->get_iterator()->iov_len);
        total_bytes += retval > 0 ? retval : 0;
        io_vector->update_iterator(retval);
    } while (retval > 0 && io_vector->get_remain_count() > 0);

    return total_bytes > 0 ? total_bytes : retval;
}

ssize_t UringSocket::ssl_recv(void *_buf, size_t _n) {
    while (true) {
        int n = SSL_read(socket->ssl, _buf, _n);
        if (!ssl_bio_prepare()) {
            return -1;
        }
        if (n > 0) {
            return n;
        }
        if (!ssl_bio_perform(n, "ssl_recv")) {
            return -1;
        }
    }
}

ssize_t UringSocket::ssl_send(const void *_buf, size_t _n) {
    while (true) {
        int n = SSL_write(socket->ssl, _buf, _n);
        if (!ssl_bio_prepare()) {
            return -1;
        }
        if (n > 0) {
            return n;
        }
        if (!ssl_bio_perform(n, "ssl_send")) {
            return -1;
        }
    }
}

ssize_t UringSocket::ssl_sendfile(const File &file, off_t *offset, size_t size) {
    char buf[SW_BUFFER_SIZE_BIG];
    size_t total = 0;

    while (total < size) {
        ssize_t readn = size > sizeof(buf) ? sizeof(buf) : size;
        ssize_t n = file.pread(buf, readn, *offset);
        if (n > 0) {
            ssize_t ret = ssl_send(buf, n);
            if (ret < 0) {
                if (socket->catch_write_error(errno) == SW_ERROR) {
                    swoole_sys_warning("write() failed");
                }
            } else {
                *offset += ret;
                total += ret;
            }
            swoole_trace_log(SW_TRACE_REACTOR, "fd=%d, readn=%ld, n=%ld, ret=%ld", fd, readn, n, ret);
        } else {
            swoole_sys_warning("pread() failed");
            return total;
        }
    }

    return -1;
}
};  // namespace coroutine
};  // namespace swoole
#endif
