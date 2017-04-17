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

static int swPipeUnsock_read(swPipe *p, void *data, int length);
static int swPipeUnsock_write(swPipe *p, void *data, int length);
static int swPipeUnsock_getFd(swPipe *p, int master);
static int swPipeUnsock_close(swPipe *p);

typedef struct _swPipeUnsock
{
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

static int swPipeUnsock_getFd(swPipe *p, int master)
{
    swPipeUnsock *this = p->object;
    return master == 1 ? this->socks[1] : this->socks[0];
}

static int swPipeUnsock_close(swPipe *p)
{
    swPipeUnsock *object = p->object;
    int ret = swPipeUnsock_close_ext(p, 0);
    sw_free(object);
    return ret;
}

int swPipeUnsock_close_ext(swPipe *p, int which)
{
    int ret1 = 0, ret2 = 0;
    swPipeUnsock *object = p->object;

    if (which == SW_PIPE_CLOSE_MASTER)
    {
        if (object->pipe_master_closed)
        {
            return SW_ERR;
        }
        ret1 = close(object->socks[1]);
        object->pipe_master_closed = 1;
    }
    else if (which == SW_PIPE_CLOSE_WORKER)
    {
        if (object->pipe_worker_closed)
        {
            return SW_ERR;
        }
        ret1 = close(object->socks[0]);
        object->pipe_worker_closed = 1;
    }
    else
    {
        ret1 = swPipeUnsock_close_ext(p, SW_PIPE_CLOSE_MASTER);
        ret2 = swPipeUnsock_close_ext(p, SW_PIPE_CLOSE_WORKER);
    }

    return 0 - ret1 - ret2;
}

int swPipeUnsock_create(swPipe *p, int blocking, int protocol)
{
    int ret;
    swPipeUnsock *object = sw_malloc(sizeof(swPipeUnsock));
    if (object == NULL)
    {
        swWarn("malloc() failed.");
        return SW_ERR;
    }
    bzero(object, sizeof(swPipeUnsock));
    p->blocking = blocking;
    ret = socketpair(AF_UNIX, protocol, 0, object->socks);
    if (ret < 0)
    {
        swWarn("socketpair() failed. Error: %s [%d]", strerror(errno), errno);
        sw_free(object);
        return SW_ERR;
    }
    else
    {
        //Nonblock
        if (blocking == 0)
        {
            swSetNonBlock(object->socks[0]);
            swSetNonBlock(object->socks[1]);
        }

        int sbsize = SwooleG.socket_buffer_size;
        swSocket_set_buffer_size(object->socks[0], sbsize);
        swSocket_set_buffer_size(object->socks[1], sbsize);

        p->object = object;
        p->read = swPipeUnsock_read;
        p->write = swPipeUnsock_write;
        p->getFd = swPipeUnsock_getFd;
        p->close = swPipeUnsock_close;
    }
    return 0;
}

static int swPipeUnsock_read(swPipe *p, void *data, int length)
{
    return read(((swPipeUnsock *) p->object)->socks[0], data, length);
}

static int swPipeUnsock_write(swPipe *p, void *data, int length)
{
    return write(((swPipeUnsock *) p->object)->socks[1], data, length);
}
