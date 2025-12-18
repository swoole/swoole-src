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
#ifdef SW_USE_OPENSSL
    BIO *rbio = nullptr;
    BIO *wbio = nullptr;

    bool ssl_bio_write();
    bool ssl_bio_read();
    ssize_t ssl_recv(void *_buf, size_t _n);
    ssize_t ssl_send(const void *_buf, size_t _n);
#endif

    ssize_t uring_send(const void *_buf, size_t _n);
    ssize_t uring_recv(void *_buf, size_t _n);
    network::Socket *uring_accept(double timeout);

    bool is_ssl() {
#ifdef SW_USE_OPENSSL
        return !!socket->ssl;
#else
        return false;
#endif
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

    bool connect(const sockaddr *addr, socklen_t addrlen) override;
    UringSocket *accept(double timeout = 0);
    ssize_t recv(void *_buf, size_t _n) override;
    ssize_t send(const void *_buf, size_t _n) override;
    ssize_t recv_all(void *_buf, size_t _n) override;
    ssize_t send_all(const void *_buf, size_t _n) override;
#ifdef SW_USE_OPENSSL
    bool ssl_handshake() override;
#endif
};
}  // namespace coroutine
}  // namespace swoole
