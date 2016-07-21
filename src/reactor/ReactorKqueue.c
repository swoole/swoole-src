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
#include <string.h>

#ifdef IDE_HELPER
#ifdef HAVE_KQUEUE
#include <sys/event.h>
#else
#include "helper/kqueue.h"
#define HAVE_KQUEUE
#endif
#else
#ifdef HAVE_KQUEUE
#include <sys/event.h>
#endif
#endif

#ifdef HAVE_KQUEUE

typedef struct swReactorKqueue_s swReactorKqueue;
typedef struct _swFd
{
    uint32_t fd;
    uint32_t fdtype;
} swFd;

static int swReactorKqueue_add(swReactor *reactor, int fd, int fdtype);
static int swReactorKqueue_set(swReactor *reactor, int fd, int fdtype);
static int swReactorKqueue_del(swReactor *reactor, int fd);
static int swReactorKqueue_wait(swReactor *reactor, struct timeval *timeo);
static void swReactorKqueue_free(swReactor *reactor);

struct swReactorKqueue_s
{
    int epfd;
    int event_max;
    struct kevent *events;
};

int swReactorKqueue_create(swReactor *reactor, int max_event_num)
{
    //create reactor object
    swReactorKqueue *reactor_object = sw_malloc(sizeof(swReactorKqueue));
    if (reactor_object == NULL)
    {
        swTrace("[swReactorKqueueCreate] malloc[0] fail\n");
        return SW_ERR;
    }
    bzero(reactor_object, sizeof(swReactorKqueue));

    reactor->object = reactor_object;
    reactor->max_event_num = max_event_num;
    reactor_object->events = sw_calloc(max_event_num, sizeof(struct kevent));

    if (reactor_object->events == NULL)
    {
        swTrace("[swReactorKqueueCreate] malloc[1] fail\n");
        return SW_ERR;
    }
    //kqueue create
    reactor_object->event_max = max_event_num;
    reactor_object->epfd = kqueue();
    if (reactor_object->epfd < 0)
    {
        swTrace("[swReactorKqueueCreate] kqueue_create[0] fail\n");
        return SW_ERR;
    }

    //binding method
    reactor->add = swReactorKqueue_add;
    reactor->set = swReactorKqueue_set;
    reactor->del = swReactorKqueue_del;
    reactor->wait = swReactorKqueue_wait;
    reactor->free = swReactorKqueue_free;

    return SW_OK;
}

static void swReactorKqueue_free(swReactor *reactor)
{
    swReactorKqueue *this = reactor->object;
    close(this->epfd);
    sw_free(this->events);
    sw_free(this);
}

static int swReactorKqueue_add(swReactor *reactor, int fd, int fdtype)
{
    if (swReactor_add(reactor, fd, fdtype) < 0)
    {
        return SW_ERR;
    }

    swReactorKqueue *this = reactor->object;
    struct kevent e;
    swFd fd_;
    int ret;
    bzero(&e, sizeof(e));

    int fflags = 0;
    fd_.fd = fd;
    fd_.fdtype = swReactor_fdtype(fdtype);

    if (swReactor_event_read(fdtype))
    {
#ifdef NOTE_EOF
        fflags = NOTE_EOF;
#endif
        EV_SET(&e, fd, EVFILT_READ, EV_ADD, fflags, 0, NULL);
        memcpy(&e.udata, &fd_, sizeof(swFd));
        ret = kevent(this->epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0)
        {
            swSysError("add events[fd=%d#%d, type=%d, events=read] failed.", fd, reactor->id, fd_.fdtype);
            return SW_ERR;
        }
    }

    if (swReactor_event_write(fdtype))
    {
        EV_SET(&e, fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
        memcpy(&e.udata, &fd_, sizeof(swFd));
        ret = kevent(this->epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0)
        {
            swSysError("add events[fd=%d#%d, type=%d, events=write] failed.", fd, reactor->id, fd_.fdtype);
            return SW_ERR;
        }
    }

    memcpy(&e.udata, &fd_, sizeof(swFd));
    swTrace("[THREAD #%ld]EP=%d|FD=%d\n", pthread_self(), this->epfd, fd);
    reactor->event_num++;
    return SW_OK;
}

static int swReactorKqueue_set(swReactor *reactor, int fd, int fdtype)
{
    swReactorKqueue *this = reactor->object;
    struct kevent e;
    swFd fd_;
    int ret;
    bzero(&e, sizeof(e));

    int fflags = 0;
    fd_.fd = fd;
    fd_.fdtype = swReactor_fdtype(fdtype);

    if (swReactor_event_read(fdtype))
    {
#ifdef NOTE_EOF
        fflags = NOTE_EOF;
#endif
        EV_SET(&e, fd, EVFILT_READ, EV_ADD, fflags, 0, NULL);
        memcpy(&e.udata, &fd_, sizeof(swFd));
        ret = kevent(this->epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0)
        {
            swSysError("kqueue->set(%d, SW_EVENT_READ) failed.", fd);
            return SW_ERR;
        }
    }
    else
    {
        EV_SET(&e, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        memcpy(&e.udata, &fd_, sizeof(swFd));
        ret = kevent(this->epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0)
        {
            swSysError("kqueue->del(%d, SW_EVENT_READ) failed.", fd);
            return SW_ERR;
        }
    }

    if (swReactor_event_write(fdtype))
    {
        EV_SET(&e, fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
        memcpy(&e.udata, &fd_, sizeof(swFd));
        ret = kevent(this->epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0)
        {
            swSysError("kqueue->set(%d, SW_EVENT_WRITE) failed.", fd);
            return SW_ERR;
        }
    }
    else
    {
        EV_SET(&e, fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        memcpy(&e.udata, &fd_, sizeof(swFd));
        ret = kevent(this->epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0)
        {
            swSysError("kqueue->del(%d, SW_EVENT_WRITE) failed.", fd);
            return SW_ERR;
        }
    }
    //execute parent method
    swReactor_set(reactor, fd, fdtype);
    return SW_OK;
}

static int swReactorKqueue_del(swReactor *reactor, int fd)
{
    swReactorKqueue *this = reactor->object;
    struct kevent e;
    int ret;

    swConnection *socket = swReactor_get(reactor, fd);

    if (socket->events & SW_EVENT_READ)
    {
        EV_SET(&e, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        ret = kevent(this->epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0)
        {
            swSysError("kqueue->del(%d, SW_EVENT_READ) failed.", fd);
            return SW_ERR;
        }
    }

    if (socket->events & SW_EVENT_WRITE)
    {
        EV_SET(&e, fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        ret = kevent(this->epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0)
        {
            swSysError("kqueue->del(%d, SW_EVENT_WRITE) failed.", fd);
            return SW_ERR;
        }
    }

    if (swReactor_del(reactor, fd) < 0)
    {
        return SW_ERR;
    }
    reactor->event_num = reactor->event_num <= 0 ? 0 : reactor->event_num - 1;
    return SW_OK;
}

static int swReactorKqueue_wait(swReactor *reactor, struct timeval *timeo)
{
    swEvent event;
    swFd fd_;
    swReactorKqueue *object = reactor->object;
    swReactor_handle handle;

    int i, n, ret;
    struct timespec t;
    struct timespec *t_ptr;
    bzero(&t, sizeof(t));

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
        if (reactor->timeout_msec > 0)
        {
            t.tv_sec = reactor->timeout_msec / 1000;
            t.tv_nsec = (reactor->timeout_msec - t.tv_sec * 1000) * 1000;
            t_ptr = &t;
        }
        else
        {
            t_ptr = NULL;
        }

        n = kevent(object->epfd, NULL, 0, object->events, object->event_max, t_ptr);
        if (n < 0)
        {
            //swTrace("kqueue error.EP=%d | Errno=%d\n", object->epfd, errno);
            if (swReactor_error(reactor) < 0)
            {
                swWarn("Kqueue[#%d] Error: %s[%d]", reactor->id, strerror(errno), errno);
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
            if (object->events[i].udata)
            {
                memcpy(&fd_, &(object->events[i].udata), sizeof(fd_));
                event.fd = fd_.fd;
                event.from_id = reactor->id;
                event.type = fd_.fdtype;
                event.socket = swReactor_get(reactor, event.fd);

                //read
                if (object->events[i].filter == EVFILT_READ && !event.socket->removed)
                {
                    handle = swReactor_getHandle(reactor, SW_EVENT_READ, event.type);
                    ret = handle(reactor, &event);
                    if (ret < 0)
                    {
                        swSysError("kqueue event read socket#%d handler failed.", event.fd);
                    }
                }
                //write
                else if (object->events[i].filter == EVFILT_WRITE && !event.socket->removed)
                {
                    handle = swReactor_getHandle(reactor, SW_EVENT_WRITE, event.type);
                    ret = handle(reactor, &event);
                    if (ret < 0)
                    {
                        swSysError("kqueue event write socket#%d handler failed.", event.fd);
                    }
                }
                else
                {
                    swWarn("kqueue event unknow filter=%d", object->events[i].filter);
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
