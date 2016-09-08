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
#include <sys/select.h>

typedef struct _swFdList_node
{
    struct _swFdList_node *next, *prev;
    int fd;
    int fdtype;
} swFdList_node;

typedef struct _swReactorSelect
{
    fd_set rfds;
    fd_set wfds;
    fd_set efds;
    swFdList_node *fds;
    int maxfd;
} swReactorSelect;

#define SW_FD_SET(fd, set)    do{ if (fd<FD_SETSIZE) FD_SET(fd, set);} while(0)
#define SW_FD_CLR(fd, set)    do{ if (fd<FD_SETSIZE) FD_CLR(fd, set);} while(0)
#define SW_FD_ISSET(fd, set) ((fd < FD_SETSIZE) && FD_ISSET(fd, set))

static int swReactorSelect_add(swReactor *reactor, int fd, int fdtype);
static int swReactorSelect_wait(swReactor *reactor, struct timeval *timeo);
static void swReactorSelect_free(swReactor *reactor);
static int swReactorSelect_del(swReactor *reactor, int fd);
static int swReactorSelect_set(swReactor *reactor, int fd, int fdtype);
static int swReactorSelect_cmp(swFdList_node *a, swFdList_node *b);

int swReactorSelect_create(swReactor *reactor)
{
    //create reactor object
    swReactorSelect *object = sw_malloc(sizeof(swReactorSelect));
    if (object == NULL)
    {
        swWarn("[swReactorSelect_create] malloc[0] fail\n");
        return SW_ERR;
    }
    bzero(object, sizeof(swReactorSelect));

    object->fds = NULL;
    object->maxfd = 0;
    bzero(reactor->handle, sizeof(reactor->handle));
    reactor->object = object;
    //binding method
    reactor->add = swReactorSelect_add;
    reactor->set = swReactorSelect_set;
    reactor->del = swReactorSelect_del;
    reactor->wait = swReactorSelect_wait;
    reactor->free = swReactorSelect_free;

    return SW_OK;
}

void swReactorSelect_free(swReactor *reactor)
{
    swFdList_node *ev;
    swReactorSelect *object = reactor->object;
    LL_FOREACH(object->fds, ev)
    {
        LL_DELETE(object->fds, ev);
        sw_free(ev);
    }
    sw_free(reactor->object);
}

int swReactorSelect_add(swReactor *reactor, int fd, int fdtype)
{
    if (fd > FD_SETSIZE)
    {
        swWarn("max fd value is FD_SETSIZE(%d).\n", FD_SETSIZE);
        return SW_ERR;
    }
    if (swReactor_add(reactor, fd, fdtype) < 0)
    {
        return SW_ERR;
    }
    swReactorSelect *object = reactor->object;
    swFdList_node *ev = sw_malloc(sizeof(swFdList_node));
    ev->fd = fd;
    //select需要保存原始的值
    ev->fdtype = fdtype;
    LL_APPEND(object->fds, ev);
    reactor->event_num++;
    if (fd > object->maxfd)
    {
        object->maxfd = fd;
    }
    return SW_OK;
}

static int swReactorSelect_cmp(swFdList_node *a, swFdList_node *b)
{
    return a->fd == b->fd ? 0 : (a->fd > b->fd ? -1 : 1);
}

int swReactorSelect_del(swReactor *reactor, int fd)
{
    swReactorSelect *object = reactor->object;
    swFdList_node ev, *s_ev = NULL;
    ev.fd = fd;

    if (swReactor_del(reactor, fd) < 0)
    {
        return SW_ERR;
    }

    LL_SEARCH(object->fds, s_ev, &ev, swReactorSelect_cmp);
    if (s_ev == NULL)
    {
        swWarn("swReactorSelect: fd[%d] not found", fd);
        return SW_ERR;
    }
    LL_DELETE(object->fds, s_ev);
    SW_FD_CLR(fd, &object->rfds);
    SW_FD_CLR(fd, &object->wfds);
    SW_FD_CLR(fd, &object->efds);
    reactor->event_num = reactor->event_num <= 0 ? 0 : reactor->event_num - 1;
    sw_free(s_ev);
    return SW_OK;
}

int swReactorSelect_set(swReactor *reactor, int fd, int fdtype)
{
    swReactorSelect *object = reactor->object;
    swFdList_node ev, *s_ev = NULL;
    ev.fd = fd;
    LL_SEARCH(object->fds, s_ev, &ev, swReactorSelect_cmp);
    if (s_ev == NULL)
    {
        swWarn("swReactorSelect: sock[%d] not found.", fd);
        return SW_ERR;
    }
    s_ev->fdtype = fdtype;
    //execute parent method
    swReactor_set(reactor, fd, fdtype);
    return SW_OK;
}

int swReactorSelect_wait(swReactor *reactor, struct timeval *timeo)
{
    swReactorSelect *object = reactor->object;
    swFdList_node *ev;
    swFdList_node *tmp;
    swEvent event;
    swReactor_handle handle;
    struct timeval timeout;
    int ret;

    if (reactor->timeout_msec == 0)
    {
        if (timeo == NULL)
        {
            reactor->timeout_msec = -1;
        }
        else
        {
            reactor->timeout_msec = timeo->tv_sec * 1000 + timeo->tv_usec / 1000;
        }
    }

    while (reactor->running > 0)
    {
        FD_ZERO(&(object->rfds));
        FD_ZERO(&(object->wfds));
        FD_ZERO(&(object->efds));

        LL_FOREACH(object->fds, ev)
        {
            if (swReactor_event_read(ev->fdtype))
            {
                SW_FD_SET(ev->fd, &(object->rfds));
            }
            if (swReactor_event_write(ev->fdtype))
            {
                SW_FD_SET(ev->fd, &(object->wfds));
            }
            if (swReactor_event_error(ev->fdtype))
            {
                SW_FD_SET(ev->fd, &(object->efds));
            }
        }

        if (reactor->timeout_msec < 0)
        {
            timeout.tv_sec = SW_MAX_UINT;
            timeout.tv_usec = 0;
        }
        else
        {
            timeout.tv_sec = reactor->timeout_msec / 1000;
            timeout.tv_usec = reactor->timeout_msec - timeout.tv_sec * 1000;
        }

        ret = select(object->maxfd + 1, &(object->rfds), &(object->wfds), &(object->efds), &timeout);
        if (ret < 0)
        {
            if (swReactor_error(reactor) < 0)
            {
                swWarn("select error. Error: %s[%d]", strerror(errno), errno);
            }
            continue;
        }
        else if (ret == 0)
        {
            if (reactor->onTimeout != NULL)
            {
                reactor->onTimeout(reactor);
            }
            continue;
        }
        else
        {
            LL_FOREACH_SAFE(object->fds, ev, tmp)
            {
                event.fd = ev->fd;
                event.from_id = reactor->id;
                event.type = swReactor_fdtype(ev->fdtype);
                event.socket = swReactor_get(reactor, event.fd);

                //read
                if (SW_FD_ISSET(event.fd, &(object->rfds)) && !event.socket->removed)
                {
                    handle = swReactor_getHandle(reactor, SW_EVENT_READ, event.type);
                    ret = handle(reactor, &event);
                    if (ret < 0)
                    {
                        swSysError("[Reactor#%d] select event[type=READ, fd=%d] handler fail.", reactor->id, event.fd);
                    }
                }
                //write
                if (SW_FD_ISSET(event.fd, &(object->wfds)) && !event.socket->removed)
                {
                    handle = swReactor_getHandle(reactor, SW_EVENT_WRITE, event.type);
                    ret = handle(reactor, &event);
                    if (ret < 0)
                    {
                        swSysError("[Reactor#%d] select event[type=WRITE, fd=%d] handler fail.", reactor->id, event.fd);
                    }
                }
                //error
                if (SW_FD_ISSET(event.fd, &(object->efds)) && !event.socket->removed)
                {
                    handle = swReactor_getHandle(reactor, SW_EVENT_ERROR, event.type);
                    ret = handle(reactor, &event);
                    if (ret < 0)
                    {
                        swSysError("[Reactor#%d] select event[type=ERROR, fd=%d] handler fail.", reactor->id, event.fd);
                    }
                }
            }
            if (reactor->onFinish != NULL)
            {
                reactor->onFinish(reactor);
            }
        }
    }
    return SW_OK;
}
