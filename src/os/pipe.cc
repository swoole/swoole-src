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
    worker_socket = make_socket(worker_fd, SW_FD_PIPE);
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

void SocketPair::set_blocking(bool blocking) const {
    if (blocking) {
        worker_socket->set_block();
        master_socket->set_block();
    } else {
        worker_socket->set_nonblock();
        master_socket->set_nonblock();
    }
}

ssize_t SocketPair::read(void *data, size_t length) {
    if (blocking) {
        return worker_socket->read_sync(data, length, get_timeout_msec());
    } else {
        return worker_socket->read(data, length);
    }
}

ssize_t SocketPair::write(const void *data, size_t length) {
    if (blocking) {
        return master_socket->write_sync(data, length, get_timeout_msec());
    } else {
        return master_socket->write(data, length);
    }
}

void SocketPair::clean() {
    char buf[1024];
    while (worker_socket->wait_event(0, SW_EVENT_READ) == SW_OK) {
        if (worker_socket->read(buf, sizeof(buf)) <= 0) {
            break;
        }
    }
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
