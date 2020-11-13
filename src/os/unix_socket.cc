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

#include "swoole_pipe.h"

#include <memory>

namespace swoole {

UnixSocket::UnixSocket(bool _blocking, int _protocol):
        Pipe(_blocking) {

    if (socketpair(AF_UNIX, _protocol, 0, socks) < 0) {
        swSysWarn("socketpair() failed");
        return;
    }

    if (!init_socket(socks[1], socks[0])) {
        return;
    }

    uint32_t sbsize = network::Socket::default_buffer_size;
    master_socket->set_buffer_size(sbsize);
    worker_socket->set_buffer_size(sbsize);
}

ssize_t UnixSocket::read(void *data, size_t length) {
    return worker_socket->read(data, length);
}

ssize_t UnixSocket::write(const void *data, size_t length) {
    return master_socket->write(data, length);
}

}
