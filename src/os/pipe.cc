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
using network::Socket;

bool SocketPair::init_socket(int master_fd, int worker_fd) {
    master_socket = make_socket(master_fd, SW_FD_PIPE);
    if (master_socket == nullptr) {
    _error:
        ::close(master_fd);
        ::close(worker_fd);
        return false;
    }
    worker_socket = make_socket(worker_fd, SW_FD_PIPE);
    if (worker_socket == nullptr) {
        master_socket->free();
        ::close(worker_fd);
        goto _error;
    }
    set_blocking(blocking);
    return true;
}

Pipe::Pipe(bool _blocking) : SocketPair(_blocking) {
    if (pipe(socks) < 0) {
        swoole_sys_warning("pipe() failed");
        return;
    }
    if (!init_socket(socks[1], socks[0])) {
        return;
    }
}

ssize_t SocketPair::read(void *data, size_t length) {
    if (blocking && timeout > 0) {
        if (worker_socket->wait_event(timeout * 1000, SW_EVENT_READ) < 0) {
            return SW_ERR;
        }
    }
    return worker_socket->read(data, length);
}

ssize_t SocketPair::write(const void *data, size_t length) {
    ssize_t n = master_socket->write(data, length);
    if (blocking && n < 0 && timeout > 0 && master_socket->catch_write_error(errno) == SW_WAIT) {
        if (master_socket->wait_event(timeout * 1000, SW_EVENT_READ) < 0) {
            return SW_ERR;
        }
        n = master_socket->write(data, length);
    }
    return n;
}

bool SocketPair::close(int which) {
    if (which == SW_PIPE_CLOSE_MASTER) {
        if (master_socket == nullptr) {
            return false;
        }
        master_socket->free();
        master_socket = nullptr;
    } else if (which == SW_PIPE_CLOSE_WORKER) {
        if (worker_socket == nullptr) {
            return false;
        }
        worker_socket->free();
        worker_socket = nullptr;
    } else {
        close(SW_PIPE_CLOSE_MASTER);
        close(SW_PIPE_CLOSE_WORKER);
    }
    return true;
}

SocketPair::~SocketPair() {
    if (master_socket) {
        close(SW_PIPE_CLOSE_MASTER);
    }
    if (worker_socket) {
        close(SW_PIPE_CLOSE_WORKER);
    }
}

}  // namespace swoole
