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
#include <unordered_map>
#include <sys/select.h>

struct swReactorSelect
{
    fd_set rfds;
    fd_set wfds;
    fd_set efds;
    std::unordered_map<int, swSocket*> *fds;
    int maxfd;
};

#define SW_FD_SET(fd, set)    do{ if (fd<FD_SETSIZE) FD_SET(fd, set);} while(0)
#define SW_FD_CLR(fd, set)    do{ if (fd<FD_SETSIZE) FD_CLR(fd, set);} while(0)
#define SW_FD_ISSET(fd, set) ((fd < FD_SETSIZE) && FD_ISSET(fd, set))

static int swReactorSelect_add(swReactor *reactor, swSocket *socket, int events);
static int swReactorSelect_set(swReactor *reactor, swSocket *socket, int events);
static int swReactorSelect_del(swReactor *reactor, swSocket *socket);
static int swReactorSelect_wait(swReactor *reactor, struct timeval *timeo);
static void swReactorSelect_free(swReactor *reactor);

int swReactorSelect_create(swReactor *reactor)
{
    //create reactor object
    swReactorSelect *object = (swReactorSelect *) sw_malloc(sizeof(swReactorSelect));
    if (object == NULL)
    {
        swWarn("[swReactorSelect_create] malloc[0] fail\n");
        return SW_ERR;
    }
    bzero(object, sizeof(swReactorSelect));

    object->fds = new std::unordered_map<int, swSocket*>;
    object->maxfd = 0;
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
    swReactorSelect *object = (swReactorSelect *) reactor->object;
    delete object->fds;
    sw_free(reactor->object);
}

int swReactorSelect_add(swReactor *reactor, swSocket *socket, int events)
{
    int fd = socket->fd;
    if (fd > FD_SETSIZE)
    {
        swWarn("max fd value is FD_SETSIZE(%d).\n", FD_SETSIZE);
        return SW_ERR;
    }

    swReactorSelect *object = (swReactorSelect *) reactor->object;
    swReactor_add(reactor, socket, events);
    object->fds->emplace(fd, socket);
    if (fd > object->maxfd)
    {
        object->maxfd = fd;
    }

    return SW_OK;
}

int swReactorSelect_del(swReactor *reactor, swSocket *socket)
{
    swReactorSelect *object = (swReactorSelect *) reactor->object;
    int fd = socket->fd;
    if (object->fds->erase(fd) == 0)
    {
        swWarn("swReactorSelect: fd[%d] not found", fd);
        return SW_ERR;
    }
    SW_FD_CLR(fd, &object->rfds);
    SW_FD_CLR(fd, &object->wfds);
    SW_FD_CLR(fd, &object->efds);
    swReactor_del(reactor, socket);
    return SW_OK;
}

int swReactorSelect_set(swReactor *reactor, swSocket *socket, int events)
{
    swReactorSelect *object = (swReactorSelect *) reactor->object;
    auto i = object->fds->find(socket->fd);
    if (i == object->fds->end())
    {
        swWarn("swReactorSelect: sock[%d] not found", socket->fd);
        return SW_ERR;
    }
    swReactor_set(reactor, socket, events);
    return SW_OK;
}

int swReactorSelect_wait(swReactor *reactor, struct timeval *timeo)
{
    swReactorSelect *object = (swReactorSelect *) reactor->object;
    swEvent event;
    swReactor_handler handler;
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

    swReactor_before_wait(reactor);

    while (reactor->running > 0)
    {
        FD_ZERO(&(object->rfds));
        FD_ZERO(&(object->wfds));
        FD_ZERO(&(object->efds));

        if (reactor->onBegin != NULL)
        {
            reactor->onBegin(reactor);
        }

        for (auto i = object->fds->begin(); i != object->fds->end(); i++)
        {
            int fd = i->first;
            int events = i->second->events;
            if (swReactor_event_read(events))
            {
                SW_FD_SET(fd, &(object->rfds));
            }
            if (swReactor_event_write(events))
            {
                SW_FD_SET(fd, &(object->wfds));
            }
            if (swReactor_event_error(events))
            {
                SW_FD_SET(fd, &(object->efds));
            }
        }

        if (reactor->timeout_msec < 0)
        {
            timeout.tv_sec = UINT_MAX;
            timeout.tv_usec = 0;
        }
        else if (reactor->defer_tasks)
        {
            timeout.tv_sec = 0;
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
                swSysWarn("select error");
                break;
            }
            else
            {
                goto _continue;
            }
        }
        else if (ret == 0)
        {
            if (reactor->onTimeout)
            {
                reactor->onTimeout(reactor);
            }
            SW_REACTOR_CONTINUE;
        }
        else
        {
            for (int fd = 0; fd <= object->maxfd; fd++)
            {
                auto i = object->fds->find(fd);
                if (i == object->fds->end())
                {
                    continue;
                }
                event.socket = i->second;
                event.fd = event.socket->fd;
                event.reactor_id = reactor->id;
                event.type = event.socket->fdtype;

                //read
                if (SW_FD_ISSET(event.fd, &(object->rfds)) && !event.socket->removed)
                {
                    handler = swReactor_get_handler(reactor, SW_EVENT_READ, event.type);
                    ret = handler(reactor, &event);
                    if (ret < 0)
                    {
                        swSysWarn("[Reactor#%d] select event[type=READ, fd=%d] handler fail", reactor->id, event.fd);
                    }
                }
                //write
                if (SW_FD_ISSET(event.fd, &(object->wfds)) && !event.socket->removed)
                {
                    handler = swReactor_get_handler(reactor, SW_EVENT_WRITE, event.type);
                    ret = handler(reactor, &event);
                    if (ret < 0)
                    {
                        swSysWarn("[Reactor#%d] select event[type=WRITE, fd=%d] handler fail", reactor->id, event.fd);
                    }
                }
                //error
                if (SW_FD_ISSET(event.fd, &(object->efds)) && !event.socket->removed)
                {
                    handler = swReactor_get_handler(reactor, SW_EVENT_ERROR, event.type);
                    ret = handler(reactor, &event);
                    if (ret < 0)
                    {
                        swSysWarn("[Reactor#%d] select event[type=ERROR, fd=%d] handler fail", reactor->id, event.fd);
                    }
                }
                if (!event.socket->removed && (event.socket->events & SW_EVENT_ONCE))
                {
                    swReactorSelect_del(reactor, event.socket);
                }
            }
        }
        _continue:
        if (reactor->onFinish)
        {
            reactor->onFinish(reactor);
        }
        SW_REACTOR_CONTINUE;
    }
    return SW_OK;
}
