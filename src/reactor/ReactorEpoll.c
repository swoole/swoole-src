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

#ifdef HAVE_EPOLL
#include <sys/epoll.h>
#ifndef EPOLLRDHUP
#define EPOLLRDHUP   0x2000
#define NO_EPOLLRDHUP
#endif

#ifndef EPOLLONESHOT
#define EPOLLONESHOT (1u << 30)
#endif

typedef struct swReactorEpoll_s swReactorEpoll;

typedef struct _swFd
{
    uint32_t fd;
    uint32_t fdtype;
} swFd;

static int swReactorEpoll_add(swReactor *reactor, int fd, int fdtype);
static int swReactorEpoll_set(swReactor *reactor, int fd, int fdtype);
static int swReactorEpoll_del(swReactor *reactor, int fd);
static int swReactorEpoll_wait(swReactor *reactor, struct timeval *timeo);
static void swReactorEpoll_free(swReactor *reactor);

static sw_inline int swReactorEpoll_event_set(int fdtype)
{
    uint32_t flag = 0;
    if (swReactor_event_read(fdtype))
    {
        flag |= EPOLLIN;
    }
    if (swReactor_event_write(fdtype))
    {
        flag |= EPOLLOUT;
    }
    if (swReactor_event_error(fdtype))
    {
        //flag |= (EPOLLRDHUP);
        flag |= (EPOLLRDHUP | EPOLLHUP | EPOLLERR);
    }
    return flag;
}

struct swReactorEpoll_s
{
    int epfd;
    struct epoll_event *events;
};

int swReactorEpoll_create(swReactor *reactor, int max_event_num)
{
    //create reactor object
    swReactorEpoll *reactor_object = sw_malloc(sizeof(swReactorEpoll));
    if (reactor_object == NULL)
    {
        swWarn("malloc[0] failed.");
        return SW_ERR;
    }
    bzero(reactor_object, sizeof(swReactorEpoll));
    reactor->object = reactor_object;
    reactor->max_event_num = max_event_num;

    reactor_object->events = sw_calloc(max_event_num, sizeof(struct epoll_event));

    if (reactor_object->events == NULL)
    {
        swWarn("malloc[1] failed.");
        sw_free(reactor_object);
        return SW_ERR;
    }
    //epoll create
    reactor_object->epfd = epoll_create(512);
    if (reactor_object->epfd < 0)
    {
        swWarn("epoll_create failed. Error: %s[%d]", strerror(errno), errno);
        sw_free(reactor_object);
        return SW_ERR;
    }
    //binding method
    reactor->add = swReactorEpoll_add;
    reactor->set = swReactorEpoll_set;
    reactor->del = swReactorEpoll_del;
    reactor->wait = swReactorEpoll_wait;
    reactor->free = swReactorEpoll_free;

    return SW_OK;
}

static void swReactorEpoll_free(swReactor *reactor)
{
    swReactorEpoll *object = reactor->object;
    close(object->epfd);
    sw_free(object->events);
    sw_free(object);
}

static int swReactorEpoll_add(swReactor *reactor, int fd, int fdtype)
{
    if (swReactor_add(reactor, fd, fdtype) < 0)
    {
        return SW_ERR;
    }

    swReactorEpoll *object = reactor->object;
    struct epoll_event e;
    swFd fd_;
    int ret;
    bzero(&e, sizeof(struct epoll_event));

    fd_.fd = fd;
    fd_.fdtype = swReactor_fdtype(fdtype);
    e.events = swReactorEpoll_event_set(fdtype);

    memcpy(&(e.data.u64), &fd_, sizeof(fd_));
    ret = epoll_ctl(object->epfd, EPOLL_CTL_ADD, fd, &e);
    if (ret < 0)
    {
        swSysError("add events[fd=%d#%d, type=%d, events=%d] failed.", fd, reactor->id, fd_.fdtype, e.events);
        return SW_ERR;
    }
    swTraceLog(SW_TRACE_EVENT, "add event[reactor_id=%d|fd=%d]", reactor->id, fd);
    reactor->event_num++;
    return SW_OK;
}

static int swReactorEpoll_del(swReactor *reactor, int fd)
{
    swReactorEpoll *object = reactor->object;
    int ret;

    if (fd <= 0)
    {
        return SW_ERR;
    }
    ret = epoll_ctl(object->epfd, EPOLL_CTL_DEL, fd, NULL);
    if (ret < 0)
    {
        swSysError("epoll remove fd[%d#%d] failed.", fd, reactor->id);
        return SW_ERR;
    }

    if (swReactor_del(reactor, fd) < 0)
    {
        return SW_ERR;
    }

    reactor->event_num = reactor->event_num <= 0 ? 0 : reactor->event_num - 1;
    swTraceLog(SW_TRACE_EVENT, "remove event[reactor_id=%d|fd=%d]", reactor->id, fd);
    return SW_OK;
}

static int swReactorEpoll_set(swReactor *reactor, int fd, int fdtype)
{
    swReactorEpoll *object = reactor->object;
    swFd fd_;
    struct epoll_event e;
    int ret;

    bzero(&e, sizeof(struct epoll_event));
    e.events = swReactorEpoll_event_set(fdtype);

    if (e.events & EPOLLOUT)
    {
        assert(fd > 2);
    }

    fd_.fd = fd;
    fd_.fdtype = swReactor_fdtype(fdtype);
    memcpy(&(e.data.u64), &fd_, sizeof(fd_));

    ret = epoll_ctl(object->epfd, EPOLL_CTL_MOD, fd, &e);
    if (ret < 0)
    {
        swSysError("reactor#%d->set(fd=%d|type=%d|events=%d) failed.", reactor->id, fd, fd_.fdtype, e.events);
        return SW_ERR;
    }
    //execute parent method
    swReactor_set(reactor, fd, fdtype);
    return SW_OK;
}

static int swReactorEpoll_wait(swReactor *reactor, struct timeval *timeo)
{
    swEvent event;
    swReactorEpoll *object = reactor->object;
    swReactor_handle handle;
    int i, n, ret, msec;

    int reactor_id = reactor->id;
    int epoll_fd = object->epfd;
    int max_event_num = reactor->max_event_num;
    struct epoll_event *events = object->events;

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
        msec = reactor->timeout_msec;
        n = epoll_wait(epoll_fd, events, max_event_num, msec);
        if (n < 0)
        {
            if (swReactor_error(reactor) < 0)
            {
                swWarn("[Reactor#%d] epoll_wait failed. Error: %s[%d]", reactor_id, strerror(errno), errno);
                return SW_ERR;
            }
            else
            {
                continue;
            }
        }
        else if (n == 0)
        {
            if (reactor->onTimeout != NULL)
            {
                reactor->onTimeout(reactor);
            }
            continue;
        }
        for (i = 0; i < n; i++)
        {
            event.fd = events[i].data.u64;
            event.from_id = reactor_id;
            event.type = events[i].data.u64 >> 32;
            event.socket = swReactor_get(reactor, event.fd);

            //read
            if ((events[i].events & EPOLLIN) && !event.socket->removed)
            {
                handle = swReactor_getHandle(reactor, SW_EVENT_READ, event.type);
                ret = handle(reactor, &event);
                if (ret < 0)
                {
                    swSysError("EPOLLIN handle failed. fd=%d.", event.fd);
                }
            }
            //write
            if ((events[i].events & EPOLLOUT) && !event.socket->removed)
            {
                handle = swReactor_getHandle(reactor, SW_EVENT_WRITE, event.type);
                ret = handle(reactor, &event);
                if (ret < 0)
                {
                    swSysError("EPOLLOUT handle failed. fd=%d.", event.fd);
                }
            }
            //error
#ifndef NO_EPOLLRDHUP
            if ((events[i].events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) && !event.socket->removed)
#else
            if ((events[i].events & (EPOLLERR | EPOLLHUP)) && !event.socket->removed)
#endif
            {
                //ignore ERR and HUP, because event is already processed at IN and OUT handler.
                if ((events[i].events & EPOLLIN) || (events[i].events & EPOLLOUT))
                {
                    continue;
                }
                handle = swReactor_getHandle(reactor, SW_EVENT_ERROR, event.type);
                ret = handle(reactor, &event);
                if (ret < 0)
                {
                    swSysError("EPOLLERR handle failed. fd=%d.", event.fd);
                }
            }
        }

        if (reactor->onFinish != NULL)
        {
            reactor->onFinish(reactor);
        }
    }
    return 0;
}

#endif
