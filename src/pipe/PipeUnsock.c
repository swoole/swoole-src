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
#include "buffer.h"
#include <sys/ipc.h>
#include <sys/msg.h>

static int swPipeUnsock_read(swPipe *p, void *data, int length);
static int swPipeUnsock_write(swPipe *p, void *data, int length);
static int swPipeUnsock_getFd(swPipe *p, int isWriteFd);
static int swPipeUnsock_close(swPipe *p);

typedef struct _swPipeUnsock
{
    int socks[2];
} swPipeUnsock;

static int swPipeUnsock_getFd(swPipe *p, int isWriteFd)
{
    swPipeUnsock *this = p->object;
    return isWriteFd == 1 ? this->socks[1] : this->socks[0];
}

static int swPipeUnsock_close(swPipe *p)
{
    int ret1, ret2;
    swPipeUnsock *object = p->object;

    ret1 = close(object->socks[0]);
    ret2 = close(object->socks[1]);

    sw_free(object);

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
