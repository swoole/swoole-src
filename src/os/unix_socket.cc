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

#include "swoole_pipe.h"
#include "swoole_socket.h"

namespace swoole {
UnixSocket::UnixSocket(bool blocking, int _protocol) :
        SocketPair(blocking), protocol_(_protocol) {
    if (socketpair(AF_UNIX, protocol_, 0, socks) < 0) {
        swoole_sys_warning("socketpair() failed");
        return;
    }
    if (!init_socket(socks[1], socks[0])) {
        return;
    }
    set_buffer_size(network::Socket::default_buffer_size);
}

bool UnixSocket::set_buffer_size(size_t _size) {
    if (!master_socket->set_buffer_size(_size)) {
        return false;
    }
    if (!worker_socket->set_buffer_size(_size)) {
        return false;
    }
    return true;
}
}
