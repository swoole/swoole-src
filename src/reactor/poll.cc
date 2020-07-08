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
#include "swoole_reactor.h"
#include <poll.h>

static int swReactorPoll_add(swReactor *reactor, swSocket *socket, int events);
static int swReactorPoll_set(swReactor *reactor, swSocket *socket, int events);
static int swReactorPoll_del(swReactor *reactor, swSocket *socket);
static int swReactorPoll_wait(swReactor *reactor, struct timeval *timeo);
static void swReactorPoll_free(swReactor *reactor);
static int swReactorPoll_exist(swReactor *reactor, int fd);

typedef struct _swReactorPoll
{
    uint32_t max_fd_num;
    swSocket **fds;
    struct pollfd *events;
} swReactorPoll;

int swReactorPoll_create(swReactor *reactor, int max_fd_num)
{
    //create reactor object
    swReactorPoll *object = (swReactorPoll *) sw_malloc(sizeof(swReactorPoll));
    if (object == nullptr)
    {
        swWarn("malloc[0] failed");
        return SW_ERR;
    }
    sw_memset_zero(object, sizeof(swReactorPoll));

    object->fds = (swSocket **) sw_calloc(max_fd_num, sizeof(swSocket*));
    if (object->fds == nullptr)
    {
        swWarn("malloc[1] failed");
        sw_free(object);
        return SW_ERR;
    }
    object->events = (struct pollfd *) sw_calloc(max_fd_num, sizeof(struct pollfd));
    if (object->events == nullptr)
    {
        swWarn("malloc[2] failed");
        sw_free(object);
        return SW_ERR;
    }
    object->max_fd_num = max_fd_num;
    reactor->max_event_num = max_fd_num;
    reactor->object = object;
    reactor->add = swReactorPoll_add;
    reactor->del = swReactorPoll_del;
    reactor->set = swReactorPoll_set;
    reactor->wait = swReactorPoll_wait;
    reactor->free = swReactorPoll_free;

    return SW_OK;
}

static void swReactorPoll_free(swReactor *reactor)
{
    swReactorPoll *object = (swReactorPoll *) reactor->object;
    sw_free(object->fds);
    sw_free(reactor->object);
}

static int swReactorPoll_add(swReactor *reactor, swSocket *socket, int events)
{
    int fd = socket->fd;
    if (swReactorPoll_exist(reactor, fd))
    {
        swWarn("fd#%d is already exists", fd);
        return SW_ERR;
    }

    swReactorPoll *object = (swReactorPoll *) reactor->object;
    int cur = reactor->event_num;
    if (reactor->event_num == object->max_fd_num)
    {
        swWarn("too many connection, more than %d", object->max_fd_num);
        return SW_ERR;
    }

    swReactor_add(reactor, socket, events);

    swTrace("fd=%d, events=%d", fd, events);

    object->fds[cur] = socket;
    object->events[cur].fd = fd;
    object->events[cur].events = 0;

    if (swReactor_event_read(events))
    {
        object->events[cur].events |= POLLIN;
    }
    if (swReactor_event_write(events))
    {
        object->events[cur].events |= POLLOUT;
    }
    if (swReactor_event_error(events))
    {
        object->events[cur].events |= POLLHUP;
    }

    return SW_OK;
}

static int swReactorPoll_set(swReactor *reactor, swSocket *socket, int events)
{
    uint32_t i;
    swReactorPoll *object = (swReactorPoll *) reactor->object;

    swTrace("fd=%d, events=%d", socket->fd, events);

    for (i = 0; i < reactor->event_num; i++)
    {
        //found
        if (object->events[i].fd == socket->fd)
        {
            object->events[i].events = 0;
            if (swReactor_event_read(events))
            {
                object->events[i].events |= POLLIN;
            }
            if (swReactor_event_write(events))
            {
                object->events[i].events |= POLLOUT;
            }
            //execute parent method
            swReactor_set(reactor, socket, events);
            return SW_OK;
        }
    }

    return SW_ERR;
}

static int swReactorPoll_del(swReactor *reactor, swSocket *socket)
{
    uint32_t i;
    swReactorPoll *object = (swReactorPoll *) reactor->object;

    for (i = 0; i < reactor->event_num; i++)
    {
        if (object->events[i].fd == socket->fd)
        {
            for (; i < reactor->event_num; i++)
            {
                if (i == reactor->event_num)
                {
                    object->fds[i] = nullptr;
                    object->events[i].fd = 0;
                    object->events[i].events = 0;
                }
                else
                {
                    object->fds[i] = object->fds[i + 1];
                    object->events[i] = object->events[i + 1];
                }
            }
            swReactor_del(reactor, socket);
            return SW_OK;
        }
    }
    return SW_ERR;
}

static int swReactorPoll_wait(swReactor *reactor, struct timeval *timeo)
{
    swReactorPoll *object = (swReactorPoll *) reactor->object;
    swEvent event;
    swReactor_handler handler;

    int ret;

    if (reactor->timeout_msec == 0)
    {
        if (timeo == nullptr)
        {
            reactor->timeout_msec = -1;
        }
        else
        {
            reactor->timeout_msec = timeo->tv_sec * 1000 + timeo->tv_usec / 1000;
        }
    }

    swReactor_before_wait(reactor);

    while (reactor->running > 0)
    {
        if (reactor->onBegin != nullptr)
        {
            reactor->onBegin(reactor);
        }
        ret = poll(object->events, reactor->event_num, swReactor_get_timeout_msec(reactor));
        if (ret < 0)
        {
            if (swReactor_error(reactor) < 0)
            {
                swSysWarn("poll error");
                break;
            }
            else
            {
                goto _continue;
            }
        }
        else if (ret == 0)
        {
            reactor->execute_end_callbacks(true);
            SW_REACTOR_CONTINUE;
        }
        else
        {
            for (uint32_t i = 0; i < reactor->event_num; i++)
            {
                event.socket = object->fds[i];
                event.fd = object->events[i].fd;
                event.reactor_id = reactor->id;
                event.type = event.socket->fdtype;

                swTrace("Event: fd=%d|reactor_id=%d|type=%d", event.fd, reactor->id, event.type);
                //in
                if ((object->events[i].revents & POLLIN) && !event.socket->removed)
                {
                    if (object->events[i].revents & (POLLHUP | POLLERR))
                    {
                        event.socket->event_hup = 1;
                    }
                    handler = swReactor_get_handler(reactor, SW_EVENT_READ, event.type);
                    ret = handler(reactor, &event);
                    if (ret < 0)
                    {
                        swSysWarn("poll[POLLIN] handler failed. fd=%d", event.fd);
                    }
                }
                //out
                if ((object->events[i].revents & POLLOUT) && !event.socket->removed)
                {
                    handler = swReactor_get_handler(reactor, SW_EVENT_WRITE, event.type);
                    ret = handler(reactor, &event);
                    if (ret < 0)
                    {
                        swSysWarn("poll[POLLOUT] handler failed. fd=%d", event.fd);
                    }
                }
                //error
                if ((object->events[i].revents & (POLLHUP | POLLERR)) && !event.socket->removed)
                {
                    //ignore ERR and HUP, because event is already processed at IN and OUT handler.
                    if ((object->events[i].revents & POLLIN) || (object->events[i].revents & POLLOUT))
                    {
                        continue;
                    }
                    handler = swReactor_get_handler(reactor, SW_EVENT_ERROR, event.type);
                    ret = handler(reactor, &event);
                    if (ret < 0)
                    {
                        swSysWarn("poll[POLLERR] handler failed. fd=%d", event.fd);
                    }
                }
                if (!event.socket->removed && (event.socket->events & SW_EVENT_ONCE))
                {
                    swReactorPoll_del(reactor, event.socket);
                }
            }
        }
        _continue:
        reactor->execute_end_callbacks(false);
        SW_REACTOR_CONTINUE;
    }
    return SW_OK;
}

static int swReactorPoll_exist(swReactor *reactor, int fd)
{
    swReactorPoll *object = (swReactorPoll *) reactor->object;
    for (uint32_t i = 0; i < reactor->event_num; i++)
    {
        if (object->events[i].fd == fd)
        {
            return SW_TRUE;
        }
    }
    return SW_FALSE;
}
