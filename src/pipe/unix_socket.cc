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
#include "pipe.h"
#include "swoole_log.h"

static ssize_t swPipeUnsock_read(swPipe *p, void *data, size_t length);
static ssize_t swPipeUnsock_write(swPipe *p, const void *data, size_t length);
static void swPipeUnsock_close(swPipe *p);

struct swPipeUnsock {
    /**
     * master : socks[1]
     * worker : socks[0]
     */
    int socks[2];
    /**
     * master pipe is closed
     */
    bool pipe_master_closed;
    /**
     * worker pipe is closed
     */
    bool pipe_worker_closed;
};

static void swPipeUnsock_close(swPipe *p) {
    swPipeUnsock *object = (swPipeUnsock *) p->object;
    swPipeUnsock_close_ext(p, 0);
    delete object;
}

int swPipeUnsock_close_ext(swPipe *p, int which) {
    swPipeUnsock *object = (swPipeUnsock *) p->object;

    if (which == SW_PIPE_CLOSE_MASTER) {
        if (object->pipe_master_closed) {
            return SW_ERR;
        }
        p->master_socket->free();
        object->pipe_master_closed = true;
    } else if (which == SW_PIPE_CLOSE_WORKER) {
        if (object->pipe_worker_closed) {
            return SW_ERR;
        }
        p->worker_socket->free();
        object->pipe_worker_closed = true;
    } else {
        swPipeUnsock_close_ext(p, SW_PIPE_CLOSE_MASTER);
        swPipeUnsock_close_ext(p, SW_PIPE_CLOSE_WORKER);
    }

    return SW_OK;
}

int swPipeUnsock_create(swPipe *p, int blocking, int protocol) {
    int ret;
    std::unique_ptr<swPipeUnsock> object(new swPipeUnsock());
    p->blocking = blocking;
    ret = socketpair(AF_UNIX, protocol, 0, object->socks);
    if (ret < 0) {
        swSysWarn("socketpair() failed");
        return SW_ERR;
    }

    if (swPipe_init_socket(p, object->socks[1], object->socks[0], blocking) < 0) {
        return SW_ERR;
    }

    uint32_t sbsize = swoole::network::Socket::default_buffer_size;
    p->master_socket->set_buffer_size(sbsize);
    p->worker_socket->set_buffer_size(sbsize);

    p->object = object.release();
    p->read = swPipeUnsock_read;
    p->write = swPipeUnsock_write;
    p->getSocket = swPipe_getSocket;
    p->close = swPipeUnsock_close;

    return 0;
}

static ssize_t swPipeUnsock_read(swPipe *p, void *data, size_t length) {
    return read(((swPipeUnsock *) p->object)->socks[0], data, length);
}

static ssize_t swPipeUnsock_write(swPipe *p, const void *data, size_t length) {
    return write(((swPipeUnsock *) p->object)->socks[1], data, length);
}
