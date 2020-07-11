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

#include "swoole.h"
#include "pipe.h"
#include "swoole_log.h"

static int swPipeUnsock_read(swPipe *p, void *data, int length);
static int swPipeUnsock_write(swPipe *p, const void *data, int length);
static int swPipeUnsock_close(swPipe *p);

typedef struct _swPipeUnsock {
    /**
     * master : socks[1]
     * worker : socks[0]
     */
    int socks[2];
    /**
     * master pipe is closed
     */
    uint8_t pipe_master_closed;
    /**
     * worker pipe is closed
     */
    uint8_t pipe_worker_closed;
} swPipeUnsock;

static int swPipeUnsock_close(swPipe *p) {
    swPipeUnsock *object = (swPipeUnsock *) p->object;
    int ret = swPipeUnsock_close_ext(p, 0);
    sw_free(object);
    return ret;
}

int swPipeUnsock_close_ext(swPipe *p, int which) {
    swPipeUnsock *object = (swPipeUnsock *) p->object;

    if (which == SW_PIPE_CLOSE_MASTER) {
        if (object->pipe_master_closed) {
            return SW_ERR;
        }
        swSocket_free(p->master_socket);
        object->pipe_master_closed = 1;
    } else if (which == SW_PIPE_CLOSE_WORKER) {
        if (object->pipe_worker_closed) {
            return SW_ERR;
        }
        swSocket_free(p->worker_socket);
        ;
        object->pipe_worker_closed = 1;
    } else {
        swPipeUnsock_close_ext(p, SW_PIPE_CLOSE_MASTER);
        swPipeUnsock_close_ext(p, SW_PIPE_CLOSE_WORKER);
    }

    return SW_OK;
}

int swPipeUnsock_create(swPipe *p, int blocking, int protocol) {
    int ret;
    swPipeUnsock *object = (swPipeUnsock *) sw_malloc(sizeof(swPipeUnsock));
    if (object == nullptr) {
        swWarn("malloc() failed");
        return SW_ERR;
    }
    sw_memset_zero(object, sizeof(swPipeUnsock));
    p->blocking = blocking;
    ret = socketpair(AF_UNIX, protocol, 0, object->socks);
    if (ret < 0) {
        swSysWarn("socketpair() failed");
        sw_free(object);
        return SW_ERR;
    } else {
        if (swPipe_init_socket(p, object->socks[1], object->socks[0], blocking) < 0) {
            sw_free(object);
            return SW_ERR;
        }

        uint32_t sbsize = SwooleG.socket_buffer_size;
        swSocket_set_buffer_size(p->master_socket, sbsize);
        swSocket_set_buffer_size(p->worker_socket, sbsize);

        p->object = object;
        p->read = swPipeUnsock_read;
        p->write = swPipeUnsock_write;
        p->getSocket = swPipe_getSocket;
        p->close = swPipeUnsock_close;
    }
    return 0;
}

static int swPipeUnsock_read(swPipe *p, void *data, int length) {
    return read(((swPipeUnsock *) p->object)->socks[0], data, length);
}

static int swPipeUnsock_write(swPipe *p, const void *data, int length) {
    return write(((swPipeUnsock *) p->object)->socks[1], data, length);
}
