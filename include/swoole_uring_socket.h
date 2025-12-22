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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole_coroutine_socket.h"

namespace swoole {
namespace coroutine {
class UringSocket : public Socket {
    BIO *rbio = nullptr;
    BIO *wbio = nullptr;

    bool ssl_bio_write();
    bool ssl_bio_read();
    bool ssl_bio_prepare();
    bool ssl_bio_perform(int rc, const char *fn);
    ssize_t ssl_recv(void *_buf, size_t _n);
    ssize_t ssl_send(const void *_buf, size_t _n);
    ssize_t ssl_readv(network::IOVector *io_vector);
    ssize_t ssl_writev(network::IOVector *io_vector);
    ssize_t ssl_sendfile(const File &file, off_t *offset, size_t size);

    ssize_t uring_send(const void *_buf, size_t _n);
    ssize_t uring_recv(void *_buf, size_t _n);
    ssize_t uring_readv(const struct iovec *iovec, int count);
    ssize_t uring_writev(const struct iovec *iovec, int count);
    ssize_t uring_sendfile(const File &file, off_t *offset, size_t size);
    network::Socket *uring_accept(double timeout);

    bool is_ssl() {
        return !!socket->ssl;
    }

  public:
    UringSocket(SocketType sock_type) : Socket(sock_type) {}
    UringSocket(int domain, int type, int protocol) : Socket(domain, type, protocol) {}
    UringSocket(int _fd, int _domain, int _type, int _protocol) : Socket(_fd, _domain, _type, _protocol) {}
    UringSocket(int _fd, SocketType _type) : Socket(_fd, _type) {}
    UringSocket(network::Socket *sock, const UringSocket *server_sock) : Socket(sock, server_sock) {}

    bool connect(const std::string &_host, int _port = 0, int flags = 0) {
        return Socket::connect(_host, _port, flags);
    }

    ssize_t recvfrom(void *_buf, size_t _n) {
        return Socket::recvfrom(_buf, _n);
    }

    bool connect(const sockaddr *addr, socklen_t addrlen) override;
    UringSocket *accept(double timeout = 0);

    ssize_t read(void *_buf, size_t _n) override;
    ssize_t write(const void *_buf, size_t _n) override;
    ssize_t recvmsg(msghdr *msg, int flags) override;
    ssize_t sendmsg(const msghdr *msg, int flags) override;
    ssize_t recvfrom(void *_buf, size_t _n, sockaddr *_addr, socklen_t *_socklen) override;
    ssize_t sendto(const std::string &host, int port, const void *_buf, size_t _n) override;
    ssize_t recv(void *_buf, size_t _n) override;
    ssize_t send(const void *_buf, size_t _n) override;
    ssize_t recv_all(void *_buf, size_t _n) override;
    ssize_t send_all(const void *_buf, size_t _n) override;
    bool sendfile(const char *filename, off_t offset, size_t length) override;
    ssize_t readv(network::IOVector *io_vector) override;
    ssize_t readv_all(network::IOVector *io_vector) override;
    ssize_t writev(network::IOVector *io_vector) override;
    ssize_t writev_all(network::IOVector *io_vector) override;
    bool ssl_handshake() override;
};
}  // namespace coroutine
}  // namespace swoole
