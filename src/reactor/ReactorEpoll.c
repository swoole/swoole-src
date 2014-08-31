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

#pragma pack(4)
typedef struct _swFd
{
    uint32_t fd;
    uint32_t fdtype;
} swFd;
#pragma pack()

static int swReactorEpoll_add(swReactor *reactor, int fd, int fdtype);
static int swReactorEpoll_set(swReactor *reactor, int fd, int fdtype);
static int swReactorEpoll_del(swReactor *reactor, int fd);
static int swReactorEpoll_wait(swReactor *reactor, struct timeval *timeo);
static void swReactorEpoll_free(swReactor *reactor);

static sw_inline int swReactorEpoll_event_set(int fdtype)
{
    uint32_t flag = 0;
#ifdef SW_USE_EPOLLET
    flag = EPOLLET;
#endif

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
        return SW_ERR;
    }
    //epoll create
    reactor_object->epfd = epoll_create(512);
    if (reactor_object->epfd < 0)
    {
        swWarn("epoll_create failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    //binding method
    reactor->add = swReactorEpoll_add;
    reactor->set = swReactorEpoll_set;
    reactor->del = swReactorEpoll_del;
    reactor->wait = swReactorEpoll_wait;
    reactor->free = swReactorEpoll_free;
    reactor->setHandle = swReactor_setHandle;
    reactor->onFinish = NULL;
    reactor->onTimeout = NULL;
    return SW_OK;
}

void swReactorEpoll_free(swReactor *reactor)
{
    swReactorEpoll *object = reactor->object;
    close(object->epfd);
    sw_free(object->events);
    sw_free(object);
}

int swReactorEpoll_add(swReactor *reactor, int fd, int fdtype)
{
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
        swWarn("add event failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    swTraceLog(SW_TRACE_EVENT, "add event[reactor_id=%d|fd=%d]", reactor->id, fd);
    reactor->event_num++;
    return SW_OK;
}

int swReactorEpoll_del(swReactor *reactor, int fd)
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
        swWarn("epoll remove fd[=%d] failed. Error: %s[%d]", fd, strerror(errno), errno);
        return SW_ERR;
    }
    //close时会自动从epoll事件中移除
    //swoole中未使用dup
    ret = close(fd);
    if (ret >= 0)
    {
        (reactor->event_num <= 0) ? reactor->event_num = 0 : reactor->event_num--;
    }
    swTraceLog(SW_TRACE_EVENT, "remove event[reactor_id=%d|fd=%d]", reactor->id, fd);
    return SW_OK;
}

int swReactorEpoll_set(swReactor *reactor, int fd, int fdtype)
{
    swReactorEpoll *object = reactor->object;
    swFd fd_;
    struct epoll_event e;
    int ret;

    bzero(&e, sizeof(struct epoll_event));
    e.events = swReactorEpoll_event_set(fdtype);
    fd_.fd = fd;
    fd_.fdtype = swReactor_fdtype(fdtype);
    memcpy(&(e.data.u64), &fd_, sizeof(fd_));

    ret = epoll_ctl(object->epfd, EPOLL_CTL_MOD, fd, &e);
    if (ret < 0)
    {
        swWarn("set event[reactor_id=%d|fd=%d|type=%d|events=%d] failed. Error: %s[%d]", reactor->id, fd, fd_.fdtype,
                e.events, strerror(errno), errno);
        return SW_ERR;
    }
    return SW_OK;
}

int swReactorEpoll_wait(swReactor *reactor, struct timeval *timeo)
{
    swEvent ev;
    swReactorEpoll *object = reactor->object;
    swReactor_handle handle;
    int i, n, ret, usec;

    int reactor_id = reactor->id;
    int epoll_fd = object->epfd;
    int max_event_num = reactor->max_event_num;
    struct epoll_event *events = object->events;

    if (timeo == NULL)
    {
        usec = SW_MAX_UINT;
    }
    else
    {
        usec = timeo->tv_sec * 1000 + timeo->tv_usec / 1000;
    }

    while (SwooleG.running > 0)
    {
        n = epoll_wait(epoll_fd, events, max_event_num, usec);
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
            ev.fd = events[i].data.u64;
            ev.from_id = reactor_id;
            ev.type = events[i].data.u64 >> 32;

            //read
            if (events[i].events & EPOLLIN)
            {
                //read
                handle = swReactor_getHandle(reactor, SW_EVENT_READ, ev.type);
                ret = handle(reactor, &ev);
                if (ret < 0)
                {
                    swWarn("[Reactor#%d] epoll [EPOLLIN] handle failed. fd=%d. Error: %s[%d]", reactor_id, ev.fd, strerror(errno), errno);
                }
            }
            //write, ev.fd == 0, connection is closed.
            if ((events[i].events & EPOLLOUT) && ev.fd > 0)
            {
                handle = swReactor_getHandle(reactor, SW_EVENT_WRITE, ev.type);
                ret = handle(reactor, &ev);
                if (ret < 0)
                {
                    swWarn("[Reactor#%d] epoll [EPOLLOUT] handle failed. fd=%d. Error: %s[%d]", reactor_id, ev.fd, strerror(errno), errno);
                }
            }
            //error
#ifndef NO_EPOLLRDHUP
            if ((events[i].events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) && ev.fd > 0)
#else
            if ((events[i].events & (EPOLLERR | EPOLLHUP)) && ev.fd > 0)
#endif
            {
                handle = swReactor_getHandle(reactor, SW_EVENT_ERROR, ev.type);
                ret = handle(reactor, &ev);
                if (ret < 0)
                {
                    swWarn("[Reactor#%d] epoll [EPOLLERR] handle failed. fd=%d. Error: %s[%d]", reactor_id, ev.fd, strerror(errno), errno);
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
