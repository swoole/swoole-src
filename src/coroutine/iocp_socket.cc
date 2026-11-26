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

#include "swoole_iocp_socket.h"
#include "swoole_coroutine_system.h"
#include "swoole_iocp.h"
#include "swoole_reactor.h"
#include "swoole_util.h"

#if defined(_WIN32) && defined(SW_USE_IOCP_SOCKET)

typedef swoole::network::Socket NetSocket;

namespace swoole {
namespace coroutine {

IocpSocket::IoBinding::IoBinding(IocpSocket *socket, EventType mask) : owner(socket), events(mask) {
    auto *co = Coroutine::get_current_safe();
    if (events & SW_EVENT_READ) {
        owner->read_co = co;
    }
    if (events & SW_EVENT_WRITE) {
        owner->write_co = co;
    }
}

IocpSocket::IoBinding::~IoBinding() {
    if (events & SW_EVENT_READ) {
        owner->read_co = nullptr;
    }
    if (events & SW_EVENT_WRITE) {
        owner->write_co = nullptr;
    }
    if (sw_unlikely(!owner->close_waiters.empty()) && !owner->has_bound()) {
        owner->notify_close_waiters();
    }
}

void IocpSocket::notify_close_waiters() {
    std::vector<std::shared_ptr<CloseWaiter>> waiters;
    waiters.swap(close_waiters);
    // Resume close() after the I/O member function and its PHP caller have had
    // a chance to leave their frames. The deferred task never dereferences this
    // socket: a cancelled operation may itself close it before the task runs.
    swoole_event_defer(
        [waiters = std::move(waiters)](void *) {
            for (const auto &waiter : waiters) {
                if (waiter->waiting) {
                    waiter->waiting = false;
                    if (auto *co = Coroutine::get_by_cid(waiter->cid)) {
                        co->resume();
                    }
                }
            }
        },
        nullptr);
}

bool IocpSocket::wait_for_pending_io() {
    if (!has_bound()) {
        return true;
    }
    if (auto *co = Coroutine::get_current()) {
        auto waiter = std::make_shared<CloseWaiter>(co);
        close_waiters.push_back(waiter);
        // An uninterruptible wait keeps the PHP receiver and OVERLAPPED buffers
        // alive until Windows has completed cancellation. A manual resume must
        // not let the caller close/free a socket whose I/O is still in flight.
        do {
            co->yield();
        } while (has_bound());
        waiter->waiting = false;
    } else {
        // close() is also callable from a non-coroutine event callback. Process
        // real completions rather than polling a timer or returning early.
        while (has_bound()) {
            if (sw_reactor() && sw_reactor()->terminated) {
                set_err(SW_ERROR_CO_CANNOT_CANCEL);
                return false;
            }
            if (!SwooleTG.iocp || SwooleTG.iocp->wait(-1) < 0) {
                set_err(errno);
                return false;
            }
        }
    }
    return true;
}

bool IocpSocket::connect(const sockaddr *addr, socklen_t addrlen) {
    if (sw_unlikely(!is_available(SW_EVENT_RDWR))) {
        return false;
    }

    IoBinding binding(this, SW_EVENT_RDWR);
    int retval = Iocp::connect(socket->get_fd(), addr, addrlen, socket->connect_timeout);
    if (retval < 0) {
        set_err(errno);
        return false;
    }

    connected = true;
    socket->get_name();
    set_err(0);
    return true;
}

IocpSocket *IocpSocket::accept(double timeout) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return nullptr;
    }
    if (ssl_is_enable() && sw_unlikely(ssl_context->context == nullptr) && !ssl_context_create()) {
        return nullptr;
    }

    IoBinding binding(this, SW_EVENT_READ);
    network::Socket *conn = iocp_accept(timeout == 0 ? socket->read_timeout : timeout);

    if (conn == nullptr) {
        set_err(errno);
        return nullptr;
    }

    auto *client_sock = new IocpSocket(conn, this);
    if (sw_unlikely(client_sock->get_fd() == SW_BAD_SOCKET)) {
        swoole_sys_warning("new Socket() failed");
        set_err(errno);
        delete client_sock;
        return nullptr;
    }

    return client_sock;
}

NetSocket *IocpSocket::iocp_accept(double timeout) {
    auto *client_socket = new NetSocket();
    client_socket->info.len = sizeof(client_socket->info.addr);
    swSocketFd fd = static_cast<swSocketFd>(Iocp::accept(socket->get_fd(),
                                                         reinterpret_cast<sockaddr *>(&client_socket->info.addr),
                                                         &client_socket->info.len,
                                                         0,
                                                         timeout));
    if (fd == SW_BAD_SOCKET) {
        delete client_socket;
        return nullptr;
    }

    client_socket->fd = fd;
    client_socket->removed = 1;
    client_socket->info.type = socket->socket_type;
    client_socket->socket_type = socket->socket_type;
    client_socket->nonblock = 1;
    client_socket->cloexec = 1;
    client_socket->set_nonblock();

    return client_socket;
}

ssize_t IocpSocket::iocp_send(const void *_buf, size_t _n) {
    return Iocp::send(socket->get_fd(), _buf, _n, 0, socket->write_timeout);
}

ssize_t IocpSocket::iocp_recv(void *_buf, size_t _n) {
    ssize_t retval = Iocp::recv(socket->get_fd(), _buf, _n, 0, socket->read_timeout);
    if (retval < 0) {
        // The completion carries this read's error, even after a concurrent write updates errCode.
        set_err(errno);
    }
    return retval;
}

ssize_t IocpSocket::iocp_readv(const struct iovec *iovec, int count) {
    return Iocp::readv(socket->get_fd(), iovec, count, socket->read_timeout);
}

ssize_t IocpSocket::iocp_writev(const struct iovec *iovec, int count) {
    return Iocp::writev(socket->get_fd(), iovec, count, socket->write_timeout);
}

ssize_t IocpSocket::iocp_sendfile(const File &file, off_t *offset, size_t size) {
    return Iocp::sendfile(socket->get_fd(), file.get_fd(), offset, size, socket->write_timeout);
}

ssize_t IocpSocket::read(void *_buf, size_t _n) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    IoBinding binding(this, SW_EVENT_READ);
    ssize_t retval = Iocp::read(socket->get_fd(), _buf, _n, socket->read_timeout);
    check_return_value(retval);
    return retval;
}

ssize_t IocpSocket::write(const void *_buf, size_t _n) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }
    IoBinding binding(this, SW_EVENT_WRITE);
    ssize_t retval = Iocp::write(socket->get_fd(), _buf, _n, socket->write_timeout);
    check_return_value(retval);
    return retval;
}

ssize_t IocpSocket::recvmsg(msghdr *msg, int flags) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    IoBinding binding(this, SW_EVENT_READ);
    ssize_t retval = Iocp::recvmsg(socket->get_fd(), msg, flags, socket->read_timeout);
    check_return_value(retval);
    return retval;
}

ssize_t IocpSocket::sendmsg(const msghdr *msg, int flags) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }
    IoBinding binding(this, SW_EVENT_WRITE);
    ssize_t retval = Iocp::sendmsg(socket->get_fd(), msg, flags, socket->write_timeout);
    check_return_value(retval);
    return retval;
}

ssize_t IocpSocket::recvfrom(void *_buf, size_t _n, sockaddr *_addr, socklen_t *_socklen) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    IoBinding binding(this, SW_EVENT_READ);
    ssize_t retval = Iocp::recvfrom(socket->get_fd(), _buf, _n, _addr, _socklen, socket->read_timeout);
    check_return_value(retval);
    return retval;
}

ssize_t IocpSocket::sendto(const std::string &host, int port, const void *_buf, size_t _n) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }

    if (!socket->is_dgram()) {
        set_err(EPROTONOSUPPORT);
        return -1;
    }

    network::Address addr;
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

    IoBinding binding(this, SW_EVENT_WRITE);
    ssize_t retval = Iocp::sendto(socket->get_fd(), _buf, _n, 0, &addr.addr.ss, addr.len, socket->write_timeout);

    swoole_trace_log(SW_TRACE_SOCKET, "sendto %ld/%ld bytes, errno=%d", retval, _n, errno);

    check_return_value(retval);
    return retval;
}

ssize_t IocpSocket::recv(void *_buf, size_t _n) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }

    ssize_t retval;
    IoBinding binding(this, SW_EVENT_READ);
    if (is_ssl()) {
        retval = ssl_recv(_buf, _n);
    } else {
        retval = iocp_recv(_buf, _n);
    }

    check_return_value(retval);
    return retval;
}

ssize_t IocpSocket::send(const void *_buf, size_t _n) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }

    ssize_t retval;
    IoBinding binding(this, SW_EVENT_WRITE);
    if (is_ssl()) {
        retval = ssl_send(_buf, _n);
    } else {
        retval = iocp_send(_buf, _n);
    }

    check_return_value(retval);
    return retval;
}

ssize_t IocpSocket::recv_all(void *_buf, size_t _n) {
    ssize_t retval = 0;
    size_t total_bytes = 0;

    do {
        retval = recv(static_cast<char *>(_buf) + total_bytes, _n - total_bytes);
        if (retval <= 0) {
            break;
        }
        total_bytes += retval;
    } while (total_bytes < _n);

    check_return_value(retval);
    return retval < 0 && total_bytes == 0 ? -1 : total_bytes;
}

ssize_t IocpSocket::send_all(const void *_buf, size_t _n) {
    ssize_t retval = 0;
    size_t total_bytes = 0;

    do {
        retval = send(static_cast<const char *>(_buf) + total_bytes, _n - total_bytes);
        if (retval <= 0) {
            break;
        }
        total_bytes += retval;
    } while (total_bytes < _n);

    check_return_value(retval);
    return retval < 0 && total_bytes == 0 ? -1 : total_bytes;
}

bool IocpSocket::poll(EventType _type, double timeout) {
    if (sw_unlikely(!is_available(_type))) {
        return false;
    }

    struct pollfd fds[1];
    fds[0].events = translate_events_to_poll(_type);
    fds[0].fd = socket->get_fd();
    fds[0].revents = 0;

    auto rc = Iocp::poll(fds, 1, timeout > 0 ? static_cast<int>(timeout * 1000) : static_cast<int>(timeout));
    if (rc != 1) {
        set_err(rc == 0 ? ETIMEDOUT : errno);
        return false;
    }
    return true;
}

bool IocpSocket::sendfile(const char *filename, off_t offset, size_t length) {
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
        length = offset + length;
    }

    IoBinding binding(this, SW_EVENT_WRITE);
    ssize_t retval = is_ssl() ? ssl_sendfile(file, &offset, length) : iocp_sendfile(file, &offset, length);

    return retval == static_cast<ssize_t>(length);
}

ssize_t IocpSocket::readv(network::IOVector *io_vector) {
    ssize_t retval;
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }

    IoBinding binding(this, SW_EVENT_READ);
    do {
        if (is_ssl()) {
            retval = ssl_readv(io_vector);
        } else {
            retval = iocp_readv(io_vector->get_iterator(), io_vector->get_remain_count());
        }
        io_vector->update_iterator(retval);
    } while (retval < 0 && errno == EINTR);

    check_return_value(retval);
    return retval;
}

ssize_t IocpSocket::writev(network::IOVector *io_vector) {
    ssize_t retval;
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }

    IoBinding binding(this, SW_EVENT_WRITE);
    do {
        if (is_ssl()) {
            retval = ssl_writev(io_vector);
        } else {
            retval = iocp_writev(io_vector->get_iterator(), io_vector->get_remain_count());
        }
        io_vector->update_iterator(retval);
    } while (retval < 0 && errno == EINTR);

    check_return_value(retval);
    return retval;
}

ssize_t IocpSocket::readv_all(network::IOVector *io_vector) {
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

ssize_t IocpSocket::writev_all(network::IOVector *io_vector) {
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

bool IocpSocket::ssl_bio_write() {
    if (BIO_ctrl_pending(wbio) == 0) {
        return true;
    }
    // The SSL caller can still reference the protocol's plaintext write buffer.
    String ciphertext(SW_BUFFER_SIZE_BIG);

    while (true) {
        size_t pending = BIO_ctrl_pending(wbio);
        if (pending == 0) {
            break;
        }

        int nread = BIO_read(wbio, ciphertext.str, ciphertext.size);
        if (nread <= 0) {
            set_err(SW_ERROR_SSL_BAD_PROTOCOL);
            return false;
        }

        ssize_t written = 0;
        while (written < nread) {
            // A completion may succeed despite cancellation. Never submit the
            // next TLS fragment after close() has started draining this socket.
            if (sw_unlikely(socket->close_wait)) {
                set_err(SW_ERROR_CO_SOCKET_CLOSE_WAIT);
                return false;
            }
            ssize_t n = iocp_send(ciphertext.str + written, nread - written);
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

bool IocpSocket::ssl_bio_read() {
    // Keep TLS records separate from the partial plaintext packet in the read buffer.
    String ciphertext(SW_BUFFER_SIZE_BIG);
    ssize_t rv;
    do {
        // A completed ClientHello write must not start a new read during close().
        if (sw_unlikely(socket->close_wait)) {
            set_err(SW_ERROR_CO_SOCKET_CLOSE_WAIT);
            return false;
        }
        rv = iocp_recv(ciphertext.str, ciphertext.size);
    } while (rv < 0 && errno == EINTR);

    if (rv > 0) {
        int written = BIO_write(rbio, ciphertext.str, static_cast<int>(rv));
        if (written != rv) {
            set_err(SW_ERROR_SSL_BAD_PROTOCOL);
            return false;
        }
        return true;
    } else if (rv == 0) {
        set_err(SW_ERROR_SSL_RESET);
    }
    return false;
}

bool IocpSocket::ssl_bio_prepare() {
    if (BIO_ctrl_pending(wbio) > 0) {
        if (!ssl_bio_write()) {
            check_return_value(-1);
            return false;
        }
    }
    return true;
}

bool IocpSocket::ssl_bio_perform(int rc, const char *fn) {
    if (!ssl_bio_prepare()) {
        return false;
    }

    int error = SSL_get_error(socket->ssl, rc);
    if (error == SSL_ERROR_WANT_WRITE) {
        if (!ssl_bio_write()) {
            goto _error;
        }
        return true;
    } else if (error == SSL_ERROR_WANT_READ) {
        if (!ssl_bio_read()) {
            goto _error;
        }
        return true;
    } else if (error == SSL_ERROR_ZERO_RETURN) {
        swoole_debug("%s(fd=%d) return zero value", fn, socket->get_fd());
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
_error:
    check_return_value(-1);
    return false;
}

bool IocpSocket::ssl_handshake() {
    if (!ssl_prepare_handshake()) {
        return false;
    }
    IoBinding binding(this, SW_EVENT_RDWR);
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

    return ssl_finish_handshake();
}

ssize_t IocpSocket::ssl_readv(network::IOVector *io_vector) {
    ssize_t retval, total_bytes = 0;

    do {
        retval = ssl_recv(io_vector->get_iterator()->iov_base, io_vector->get_iterator()->iov_len);
        total_bytes += retval > 0 ? retval : 0;
        io_vector->update_iterator(retval);
    } while (retval > 0 && io_vector->get_remain_count() > 0);

    return total_bytes > 0 ? total_bytes : retval;
}

ssize_t IocpSocket::ssl_writev(network::IOVector *io_vector) {
    ssize_t retval, total_bytes = 0;

    do {
        retval = ssl_send(io_vector->get_iterator()->iov_base, io_vector->get_iterator()->iov_len);
        total_bytes += retval > 0 ? retval : 0;
        io_vector->update_iterator(retval);
    } while (retval > 0 && io_vector->get_remain_count() > 0);

    return total_bytes > 0 ? total_bytes : retval;
}

ssize_t IocpSocket::ssl_recv(void *_buf, size_t _n) {
    while (true) {
        int n = SSL_read(socket->ssl, _buf, static_cast<int>(_n));
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

ssize_t IocpSocket::ssl_send(const void *_buf, size_t _n) {
    while (true) {
        int n = SSL_write(socket->ssl, _buf, static_cast<int>(_n));
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

ssize_t IocpSocket::ssl_sendfile(const File &file, off_t *offset, size_t size) {
    char buf[SW_BUFFER_SIZE_BIG];
    size_t total = 0;

    while (total < size) {
        ssize_t readn = SW_MIN(size - total, sizeof(buf));
        ssize_t n = file.pread(buf, readn, *offset);
        if (n <= 0) {
            swoole_sys_warning("pread() failed");
            break;
        }

        ssize_t ret = ssl_send(buf, n);
        if (ret > 0) {
            *offset += ret;
            total += ret;
            swoole_trace_log(SW_TRACE_REACTOR, "fd=%d, readn=%ld, n=%ld, ret=%ld", socket->get_fd(), readn, n, ret);
        } else if (ret == 0) {
            return total;
        } else {
            switch (socket->catch_write_error(errno)) {
            case SW_ERROR:
                swoole_sys_warning("write() failed");
                return total;
            case SW_CLOSE:
                return total;
            case SW_WAIT:
            default:
                break;
            }
        }
    }

    return total;
}

}  // namespace coroutine
}  // namespace swoole

#endif
