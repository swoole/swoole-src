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

#ifdef HAVE_EVENTFD
#include <sys/eventfd.h>

static int swPipeEventfd_read(swPipe *p, void *data, int length);
static int swPipeEventfd_write(swPipe *p, void *data, int length);
static int swPipeEventfd_getFd(swPipe *p, int isWriteFd);
static int swPipeEventfd_close(swPipe *p);

typedef struct _swPipeEventfd
{
    int event_fd;
} swPipeEventfd;

int swPipeEventfd_create(swPipe *p, int blocking, int semaphore, int timeout)
{
    int efd;
    int flag = 0;
    swPipeEventfd *object = sw_malloc(sizeof(swPipeEventfd));
    if (object == NULL)
    {
        return -1;
    }

    flag = EFD_NONBLOCK;

    if (blocking == 1)
    {
        if (timeout > 0)
        {
            flag = 0;
            p->timeout = -1;
        }
        else
        {
            p->timeout = timeout;
        }
    }

#ifdef EFD_SEMAPHORE
    if (semaphore == 1)
    {
        flag |= EFD_SEMAPHORE;
    }
#endif

    p->blocking = blocking;
    efd = eventfd(0, flag);
    if (efd < 0)
    {
        swWarn("eventfd create failed. Error: %s[%d]", strerror(errno), errno);
        sw_free(object);
        return -1;
    }
    else
    {
        p->object = object;
        p->read = swPipeEventfd_read;
        p->write = swPipeEventfd_write;
        p->getFd = swPipeEventfd_getFd;
        p->close = swPipeEventfd_close;
        object->event_fd = efd;
    }
    return 0;
}

static int swPipeEventfd_read(swPipe *p, void *data, int length)
{
    int ret = -1;
    swPipeEventfd *object = p->object;

    //eventfd not support socket timeout
    if (p->blocking == 1 && p->timeout > 0)
    {
        if (swSocket_wait(object->event_fd, p->timeout * 1000, SW_EVENT_READ) < 0)
        {
            return SW_ERR;
        }
    }

    while (1)
    {
        ret = read(object->event_fd, data, sizeof(uint64_t));
        if (ret < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    }
    return ret;
}

static int swPipeEventfd_write(swPipe *p, void *data, int length)
{
    int ret;
    swPipeEventfd *this = p->object;
    while (1)
    {
        ret = write(this->event_fd, data, sizeof(uint64_t));
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
        }
        break;
    }
    return ret;
}

static int swPipeEventfd_getFd(swPipe *p, int isWriteFd)
{
    return ((swPipeEventfd *) (p->object))->event_fd;
}

static int swPipeEventfd_close(swPipe *p)
{
    int ret;
    ret = close(((swPipeEventfd *) (p->object))->event_fd);
    sw_free(p->object);
    return ret;
}

#endif
