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
  | license@php.net so we can mail you a copy immediately.               |
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
    swBuffer *write_buffer;
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

    swBuffer_free(object->write_buffer);
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

        swBuffer *buffer = swBuffer_new(sizeof(swEventData));
        if (!buffer)
        {
            swWarn("create buffer failed.");
            return SW_ERR;
        }

        object->write_buffer = buffer;

        int sbsize = SwooleG.unixsock_buffer_size;
        setsockopt(object->socks[1], SOL_SOCKET, SO_SNDBUF, &sbsize, sizeof(sbsize));
        setsockopt(object->socks[1], SOL_SOCKET, SO_RCVBUF, &sbsize, sizeof(sbsize));
        setsockopt(object->socks[0], SOL_SOCKET, SO_SNDBUF, &sbsize, sizeof(sbsize));
        setsockopt(object->socks[0], SOL_SOCKET, SO_RCVBUF, &sbsize, sizeof(sbsize));

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

static int swPipeUnsock_write(swPipe *p, void *buf, int n)
{
    swPipeUnsock *object = p->object;
    swBuffer *buffer = object->write_buffer;
    int ret;
    int pipe_used = p->pipe_used;

    if (swBuffer_empty(buffer))
    {
        ret = write(pipe_used, buf, n);

        if (ret < 0 && errno == EAGAIN)
        {
            if (SwooleWG.pipe_used == pipe_used)
            {
                SwooleG.main_reactor->set(SwooleG.main_reactor, pipe_used, SW_FD_PIPE | SW_EVENT_READ | SW_EVENT_WRITE);
            }
            else
            {
                SwooleG.main_reactor->add(SwooleG.main_reactor, pipe_used, SW_FD_PIPE | SW_EVENT_WRITE);
            }
            goto append_pipe_buffer;
        }
    }
    else
    {
        append_pipe_buffer:

        if (buffer->length > SwooleG.unixsock_buffer_size)
        {
            swWarn("Fatal Error: unix socket buffer overflow");
            return SW_ERR;
        }

        if (swBuffer_append(buffer, buf, n) < 0)
        {
            swWarn("append to pipe_buffer failed.");
            return SW_ERR;
        }
    }
    return SW_OK;
}

/**
 * pipe can write.
 */
int swPipeUnsock_onWrite(swReactor *reactor, swEvent *ev)
{
    int ret;
    swPipe *p = *(swPipe **) swArray_fetch(SwooleWG.fd_map, ev->fd);
    swPipeUnsock *object = p->object;
    swBuffer_trunk *trunk = NULL;
    swBuffer *buffer = object->write_buffer;

    while (!swBuffer_empty(buffer))
    {
        trunk = swBuffer_get_trunk(buffer);
        ret = write(ev->fd, trunk->store.ptr, trunk->length);
        if (ret < 0)
        {
            return errno == EAGAIN ? SW_OK : SW_ERR;
        }
        else
        {
            swBuffer_pop_trunk(buffer, trunk);
        }
    }

    //remove EPOLLOUT event
    if (swBuffer_empty(buffer))
    {
        if (ev->fd == SwooleWG.pipe_used)
        {
            ret = reactor->set(reactor, ev->fd, SW_FD_PIPE | SW_EVENT_READ);
        }
        else
        {
            ret = reactor->del(reactor, ev->fd);
        }
        if (ret < 0)
        {
            swSysError("reactor->set() failed.");
        }
    }
    return SW_OK;
}

