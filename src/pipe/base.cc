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
#include "pipe.h"
#include "swoole_log.h"

static int swPipeBase_read(swPipe *p, void *data, int length);
static int swPipeBase_write(swPipe *p, const void *data, int length);
static int swPipeBase_close(swPipe *p);

struct swPipeBase {
    int pipes[2];
};

int swPipe_init_socket(swPipe *p, int master_fd, int worker_fd, int blocking) {
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

swSocket *swPipe_getSocket(swPipe *p, int master) {
    return master ? p->master_socket : p->worker_socket;
}

int swPipeBase_create(swPipe *p, int blocking) {
    int ret;
    std::unique_ptr<swPipeBase> object(new swPipeBase());
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
    p->read = swPipeBase_read;
    p->write = swPipeBase_write;
    p->getSocket = swPipe_getSocket;
    p->close = swPipeBase_close;
    
    return 0;
}

static int swPipeBase_read(swPipe *p, void *data, int length) {
    if (p->blocking == 1 && p->timeout > 0) {
        if (p->worker_socket->wait_event(p->timeout * 1000, SW_EVENT_READ) < 0) {
            return SW_ERR;
        }
    }
    return read(p->worker_socket->fd, data, length);
}

static int swPipeBase_write(swPipe *p, const void *data, int length) {
    return write(p->master_socket->fd, data, length);
}

static int swPipeBase_close(swPipe *p) {
    swPipeBase *object = (swPipeBase *) p->object;
    p->master_socket->free();
    p->worker_socket->free();
    delete object;
    return SW_OK;
}
