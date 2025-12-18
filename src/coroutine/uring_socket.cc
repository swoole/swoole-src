

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
#include "swoole_iouring.h"

typedef swoole::network::Socket NetSocket;

#ifdef SW_USE_IOURING
namespace swoole {
namespace coroutine {
bool UringSocket::connect(const sockaddr *addr, socklen_t addrlen) {
    if (sw_unlikely(!is_available(SW_EVENT_RDWR))) {
        return false;
    }
    int retval = Iouring::connect(socket->get_fd(), addr, addrlen, socket->connect_timeout);
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
#ifdef SW_USE_OPENSSL
    if (ssl_is_enable() && sw_unlikely(ssl_context->context == nullptr) && !ssl_context_create()) {
        return nullptr;
    }
#endif
    network::Socket *conn = uring_accept(timeout == 0 ? socket->read_timeout : timeout);
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
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return nullptr;
    }

    auto *client_socket = new NetSocket();

    read_co = Coroutine::get_current_safe();
    int fd = Iouring::accept(socket->get_fd(),
                             reinterpret_cast<sockaddr *>(&client_socket->info.addr),
                             &client_socket->info.len,
                             SOCK_CLOEXEC | SOCK_NONBLOCK,
                             socket->read_timeout);
    read_co = nullptr;

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
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }
    write_co = Coroutine::get_current_safe();
    ssize_t retval = Iouring::send(socket->get_fd(), _buf, _n, 0, socket->write_timeout);
    write_co = nullptr;
    return retval;
}

ssize_t UringSocket::uring_recv(void *_buf, size_t _n) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    read_co = Coroutine::get_current_safe();
    ssize_t retval = Iouring::recv(socket->get_fd(), _buf, _n, 0, socket->read_timeout);
    read_co = nullptr;
    return retval;
}

ssize_t UringSocket::ssl_recv(void *_buf, size_t _n) {
    while (true) {
        int n = SSL_read(socket->ssl, _buf, _n);
        if (n > 0) {
            return n;
        }

        if (BIO_ctrl_pending(wbio) > 0) {
            if (!ssl_bio_write()) {
            _error:
                check_return_value(-1);
                return -1;
            }
        }

        int error = SSL_get_error(socket->ssl, n);
        if (error == SSL_ERROR_WANT_READ) {
            if (!ssl_bio_read()) {
                goto _error;
            }
            continue;
        } else if (error == SSL_ERROR_WANT_WRITE) {
            if (BIO_ctrl_pending(wbio) > 0) {
                if (!ssl_bio_write()) {
                    goto _error;
                }
            }
            continue;
        } else if (error == SSL_ERROR_ZERO_RETURN) {
            swoole_debug("SSL connection closed (fd=%d)", socket->fd);
            return 0;
        } else if (error == SSL_ERROR_SYSCALL) {
            if (n == 0) {
                return 0;
            }
            goto _error;
        } else {
            ulong_t err_code = ERR_get_error();
            if (err_code != 0) {
                char error_buf[512];
                ERR_error_string_n(err_code, error_buf, sizeof(error_buf));
                swoole_notice("SSL_read(fd=%d) failed: %s", socket->fd, error_buf);
                set_err(SW_ERROR_SSL_BAD_PROTOCOL, error_buf);
            } else {
                set_err(SW_ERROR_SSL_BAD_PROTOCOL);
            }
            return -1;
        }
    }
}

ssize_t UringSocket::ssl_send(const void *_buf, size_t _n) {
    while (true) {
        int n = SSL_write(socket->ssl, _buf, _n);

        if (BIO_ctrl_pending(wbio) > 0) {
            if (!ssl_bio_write()) {
            _error:
                check_return_value(-1);
                return -1;
            }
        }

        if (n > 0) {
            return n;
        }

        int error = SSL_get_error(socket->ssl, n);
        if (error == SSL_ERROR_WANT_WRITE) {
            continue;
        } else if (error == SSL_ERROR_WANT_READ) {
            if (!ssl_bio_read()) {
                return -1;
            }
            if (BIO_ctrl_pending(wbio) > 0) {
                if (!ssl_bio_write()) {
                    goto _error;
                }
            }
            continue;
        } else if (error == SSL_ERROR_ZERO_RETURN) {
            return 0;
        } else if (error == SSL_ERROR_SYSCALL) {
            goto _error;
        } else {
            ulong_t err_code = ERR_get_error();
            if (err_code != 0) {
                char error_buf[512];
                ERR_error_string_n(err_code, error_buf, sizeof(error_buf));
                swoole_notice("SSL_write(fd=%d) failed: %s", socket->fd, error_buf);
                set_err(SW_ERROR_SSL_BAD_PROTOCOL, error_buf);
            } else {
                set_err(SW_ERROR_SSL_BAD_PROTOCOL);
            }
            return -1;
        }
    }
}

ssize_t UringSocket::recv(void *_buf, size_t _n) {
    ssize_t retval;
    if (is_ssl()) {
        retval = ssl_recv(_buf, _n);
    } else {
        retval = uring_recv(_buf, _n);
    }
    check_return_value(retval);
    return retval;
}

ssize_t UringSocket::send(const void *_buf, size_t _n) {
    ssize_t retval;
    if (is_ssl()) {
        retval = ssl_send(_buf, _n);
    } else {
        retval = uring_send(_buf, _n);
    }
    check_return_value(retval);
    return retval;
}

ssize_t UringSocket::recv_all(void *_buf, size_t _n) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }

    ssize_t retval = 0;
    size_t total_bytes = 0;

    read_co = Coroutine::get_current_safe();
    do {
        retval = recv((char *) _buf + total_bytes, _n - total_bytes);
        if (retval <= 0) {
            break;
        }
        total_bytes += retval;
    } while (total_bytes < _n);
    read_co = nullptr;
    check_return_value(retval);

    return retval < 0 && total_bytes == 0 ? -1 : total_bytes;
}

ssize_t UringSocket::send_all(const void *_buf, size_t _n) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }

    ssize_t retval = 0;
    size_t total_bytes = 0;

    write_co = Coroutine::get_current_safe();
    do {
        retval = send((char *) _buf + total_bytes, _n - total_bytes);
        if (retval <= 0) {
            break;
        }
        total_bytes += retval;
    } while (total_bytes < _n);
    write_co = nullptr;
    check_return_value(retval);

    return retval < 0 && total_bytes == 0 ? -1 : total_bytes;
}

#ifdef SW_USE_OPENSSL
bool UringSocket::ssl_bio_write() {
    auto buf = get_write_buffer();

    while (true) {
        size_t pending = BIO_ctrl_pending(wbio);
        if (pending == 0) {
            break;
        }

        int nread = BIO_read(wbio, buf->str, buf->size);
        if (nread <= 0) {
            errno = SW_ERROR_SSL_HANDSHAKE_FAILED;
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
            swoole_set_last_error(SW_ERROR_SSL_HANDSHAKE_FAILED);
            return false;
        }
        return true;
    } else if (rv == 0) {
        swoole_set_last_error(SW_ERROR_SSL_RESET);
        return false;
    } else {
        if (errno == EINTR) {
            return ssl_bio_read();
        }
        swoole_set_last_error(errno);
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

    if (ssl_is_server) {
        SSL_set_accept_state(socket->ssl);
    } else {
        SSL_set_connect_state(socket->ssl);
    }

    long error;

    while (true) {
        int r = SSL_do_handshake(socket->ssl);
        if (BIO_ctrl_pending(wbio) > 0) {
            if (!ssl_bio_write()) {
            _error:
                check_return_value(-1);
                return false;
            }
        }
        if (r == 1) {
            break;
        }

        error = SSL_get_error(socket->ssl, r);
        if (error == SSL_ERROR_WANT_WRITE) {
            if (ssl_bio_write()) {
                goto _error;
            }
            continue;
        } else if (error == SSL_ERROR_WANT_READ) {
            if (!ssl_bio_read()) {
                goto _error;
            }
            continue;
        } else if (error == SSL_ERROR_ZERO_RETURN) {
            swoole_debug("SSL_connect(fd=%d) closed", fd);
            error = SW_ERROR_SSL_RESET;
            goto _error;
        } else if (error == SSL_ERROR_SYSCALL) {
            goto _error;
        } else {
            ulong_t err_code = ERR_get_error();
            char error_buf[512];
            ERR_error_string_n(err_code, error_buf, sizeof(error_buf));
            swoole_notice("ssl_connect(fd=%d) to server[%s:%d] failed. Error: %s[%ld|%d]",
                          socket->get_fd(),
                          socket->info.get_addr(),
                          socket->info.get_port(),
                          error_buf,
                          error,
                          ERR_GET_REASON(err_code));
            set_err(SW_ERROR_SSL_HANDSHAKE_FAILED, error_buf);
            return false;
        }
        break;
    }

    if (ssl_context->verify_peer) {
        if (!ssl_verify(ssl_context->allow_self_signed)) {
            return false;
        }
    }
    ssl_handshaked = true;

    return true;
}
#endif
};  // namespace coroutine
};  // namespace swoole
#endif
