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

static int swPipeBase_read(swPipe *p, void *data, int length);
static int swPipeBase_write(swPipe *p, void *data, int length);
static int swPipeBase_getFd(swPipe *p, int isWriteFd);
static int swPipeBase_close(swPipe *p);

typedef struct _swPipeBase
{
    int pipes[2];
} swPipeBase;

int swPipeBase_create(swPipe *p, int blocking)
{
    int ret;
    swPipeBase *object = sw_malloc(sizeof(swPipeBase));
    if (object == NULL)
    {
        return -1;
    }
    p->blocking = blocking;
    ret = pipe(object->pipes);
    if (ret < 0)
    {
        swWarn("pipe create fail. Error: %s[%d]", strerror(errno), errno);
        sw_free(object)
        return -1;
    }
    else
    {
        //Nonblock
        swSetNonBlock(object->pipes[0]);
        swSetNonBlock(object->pipes[1]);
        p->timeout = -1;
        p->object = object;
        p->read = swPipeBase_read;
        p->write = swPipeBase_write;
        p->getFd = swPipeBase_getFd;
        p->close = swPipeBase_close;
    }
    return 0;
}

static int swPipeBase_read(swPipe *p, void *data, int length)
{
    swPipeBase *object = p->object;
    if (p->blocking == 1 && p->timeout > 0)
    {
        if (swSocket_wait(object->pipes[0], p->timeout * 1000, SW_EVENT_READ) < 0)
        {
            return SW_ERR;
        }
    }
    return read(object->pipes[0], data, length);
}

static int swPipeBase_write(swPipe *p, void *data, int length)
{
    swPipeBase *this = p->object;
    return write(this->pipes[1], data, length);
}

static int swPipeBase_getFd(swPipe *p, int isWriteFd)
{
    swPipeBase *this = p->object;
    return (isWriteFd == 0) ? this->pipes[0] : this->pipes[1];
}

static int swPipeBase_close(swPipe *p)
{
    int ret1, ret2;
    swPipeBase *this = p->object;
    ret1 = close(this->pipes[0]);
    ret2 = close(this->pipes[1]);
    sw_free(this);
    return 0 - ret1 - ret2;
}
