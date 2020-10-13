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

#include <memory>

#include "swoole.h"
#include "swoole_socket.h"
#include "swoole_pipe.h"
#include "swoole_log.h"

using swoole::Pipe;
using swoole::network::Socket;

static ssize_t PipeBase_read(Pipe *p, void *data, size_t length);
static ssize_t PipeBase_write(Pipe *p, const void *data, size_t length);
static void PipeBase_close(Pipe *p);

struct PipeBase {
    int pipes[2];
};

int swPipe_init_socket(Pipe *p, int master_fd, int worker_fd, int blocking) {
    p->master_socket = swoole::make_socket(master_fd, SW_FD_PIPE);
    if (p->master_socket == nullptr) {
    _error:
        close(master_fd);
        close(worker_fd);
        return SW_ERR;
    }
    p->worker_socket = swoole::make_socket(worker_fd, SW_FD_PIPE);
    if (p->worker_socket == nullptr) {
        p->master_socket->free();
        close(worker_fd);
        goto _error;
    }

    if (blocking) {
        p->worker_socket->set_block();
        p->master_socket->set_block();
    } else {
        p->worker_socket->set_nonblock();
        p->master_socket->set_nonblock();
    }

    return SW_OK;
}

int swPipeBase_create(Pipe *p, int blocking) {
    int ret;
    std::unique_ptr<PipeBase> object(new PipeBase());
    p->blocking = blocking;
    ret = pipe(object->pipes);
    if (ret < 0) {
        swSysWarn("pipe() failed");
        return -1;
    }
    if (swPipe_init_socket(p, object->pipes[1], object->pipes[0], blocking) < 0) {
        return SW_ERR;
    }

    p->timeout = -1;
    p->object = object.release();
    p->read = PipeBase_read;
    p->write = PipeBase_write;
    p->close = PipeBase_close;

    return 0;
}

static ssize_t PipeBase_read(Pipe *p, void *data, size_t length) {
    if (p->blocking == 1 && p->timeout > 0) {
        if (p->worker_socket->wait_event(p->timeout * 1000, SW_EVENT_READ) < 0) {
            return SW_ERR;
        }
    }
    return p->worker_socket->read(data, length);
}

static ssize_t PipeBase_write(Pipe *p, const void *data, size_t length) {
    return p->master_socket->write(data, length);
}

static void PipeBase_close(Pipe *p) {
    PipeBase *object = (PipeBase *) p->object;
    p->master_socket->free();
    p->worker_socket->free();
    delete object;
}
