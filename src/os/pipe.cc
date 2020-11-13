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
#include "swoole_socket.h"

#include <memory>

namespace swoole {
using network::Socket;

bool Pipe::init_socket(int master_fd, int worker_fd) {
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

    if (blocking) {
        worker_socket->set_block();
        master_socket->set_block();
    } else {
        worker_socket->set_nonblock();
        master_socket->set_nonblock();
    }

    return true;
}

Pipe::Pipe(bool _blocking) {
    blocking = _blocking;
    if (pipe(socks) < 0) {
        swSysWarn("pipe() failed");
        return;
    }
    if (!init_socket(socks[1], socks[0])) {
        return;
    }
    timeout = -1;
}

ssize_t Pipe::read(void *data, size_t length) {
    if (blocking && timeout > 0) {
        if (worker_socket->wait_event(timeout * 1000, SW_EVENT_READ) < 0) {
            return SW_ERR;
        }
    }
    return worker_socket->read(data, length);
}

ssize_t Pipe::write(const void *data, size_t length) {
    return master_socket->write(data, length);
}

bool Pipe::close(int which) {
    if (which == SW_PIPE_CLOSE_MASTER) {
        if (pipe_master_closed) {
            return false;
        }
        master_socket->free();
        master_socket = nullptr;
        pipe_master_closed = true;
    } else if (which == SW_PIPE_CLOSE_WORKER) {
        if (pipe_worker_closed) {
            return false;
        }
        worker_socket->free();
        worker_socket = nullptr;
        pipe_worker_closed = true;
    } else {
        close(SW_PIPE_CLOSE_MASTER);
        close(SW_PIPE_CLOSE_WORKER);
    }
    return true;
}

Pipe::~Pipe() {
    if (!pipe_master_closed) {
        close(SW_PIPE_CLOSE_MASTER);
    }
    if (!pipe_worker_closed) {
        close(SW_PIPE_CLOSE_WORKER);
    }
}

}
