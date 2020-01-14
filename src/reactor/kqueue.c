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
#define USE_KQUEUE_IDE_HELPER
#include "helper/kqueue.h"
#define HAVE_KQUEUE
#endif
#else
#ifdef HAVE_KQUEUE
#include <sys/event.h>
#endif
#endif

#ifdef HAVE_KQUEUE

typedef struct
{
    int epfd;
    int event_max;
    struct kevent *events;
} swReactorKqueue;

static int swReactorKqueue_add(swReactor *reactor, swSocket *socket, int events);
static int swReactorKqueue_set(swReactor *reactor, swSocket *socket, int events);
static int swReactorKqueue_del(swReactor *reactor, swSocket *socket);
static int swReactorKqueue_wait(swReactor *reactor, struct timeval *timeo);
static void swReactorKqueue_free(swReactor *reactor);

static sw_inline enum swBool_type swReactorKqueue_fetch_event(swReactor *reactor, swEvent *event, void *udata)
{
    event->socket = (swSocket *) udata;
    event->fd = event->socket->fd;
    event->type = event->socket->fdtype;
    event->reactor_id = reactor->id;

    if (event->socket->removed)
    {
        return SW_FALSE;
    }
    return SW_TRUE;
}

static sw_inline void swReactorKqueue_del_once_socket(swReactor *reactor, swSocket *socket)
{
    if ((socket->events & SW_EVENT_ONCE) && !socket->removed)
    {
        swReactorKqueue_del(reactor, socket);
    }
}

int swReactorKqueue_create(swReactor *reactor, int max_event_num)
{
    //create reactor object
    swReactorKqueue *object = sw_calloc(1, sizeof(swReactorKqueue));
    if (object == NULL)
    {
        swWarn("[swReactorKqueueCreate] calloc[0] fail");
        return SW_ERR;
    }

    reactor->object = object;
    reactor->max_event_num = max_event_num;
    object->events = sw_calloc(max_event_num, sizeof(struct kevent));

    if (object->events == NULL)
    {
        swWarn("[swReactorKqueueCreate] calloc[1] fail");
        return SW_ERR;
    }
    //kqueue create
    object->event_max = max_event_num;
    object->epfd = kqueue();
    if (object->epfd < 0)
    {
        swWarn("[swReactorKqueueCreate] kqueue_create[0] fail");
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
    swReactorKqueue *object = reactor->object;
    close(object->epfd);
    sw_free(object->events);
    sw_free(object);
}

static int swReactorKqueue_add(swReactor *reactor, swSocket *socket, int events)
{
    swReactorKqueue *object = reactor->object;
    struct kevent e;
    int ret;

    int fd = socket->fd;
    int fflags = 0;

    if (swReactor_event_read(events))
    {
#ifdef NOTE_EOF
        fflags = NOTE_EOF;
#endif
        EV_SET(&e, fd, EVFILT_READ, EV_ADD, fflags, 0, socket);
        ret = kevent(object->epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0)
        {
            swSysWarn("add events[fd=%d#%d, type=%d, events=read] failed", fd, reactor->id, socket->fdtype);
            swReactor_del(reactor, socket);
            return SW_ERR;
        }
    }

    if (swReactor_event_write(events))
    {
        EV_SET(&e, fd, EVFILT_WRITE, EV_ADD, 0, 0, socket);
        ret = kevent(object->epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0)
        {
            swSysWarn("add events[fd=%d#%d, type=%d, events=write] failed", fd, reactor->id, socket->fdtype);
            swReactor_del(reactor, socket);
            return SW_ERR;
        }
    }

    swReactor_add(reactor, socket, events);
    swTraceLog(SW_TRACE_EVENT, "[THREAD #%d]EP=%d|FD=%d, events=%d", SwooleTG.id, object->epfd, fd, socket->events);

    return SW_OK;
}

static int swReactorKqueue_set(swReactor *reactor, swSocket *socket, int events)
{
    swReactorKqueue *object = reactor->object;
    struct kevent e;
    int ret;

    int fd = socket->fd;
    int fflags = 0;

    if (swReactor_event_read(events))
    {
#ifdef NOTE_EOF
        fflags = NOTE_EOF;
#endif
        EV_SET(&e, fd, EVFILT_READ, EV_ADD, fflags, 0, socket);
        ret = kevent(object->epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0)
        {
            swSysWarn("kqueue->set(%d, SW_EVENT_READ) failed", fd);
            return SW_ERR;
        }
    }
    else
    {
        EV_SET(&e, fd, EVFILT_READ, EV_DELETE, 0, 0, socket);
        ret = kevent(object->epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0)
        {
            swSysWarn("kqueue->del(%d, SW_EVENT_READ) failed", fd);
            return SW_ERR;
        }
    }

    if (swReactor_event_write(events))
    {
        EV_SET(&e, fd, EVFILT_WRITE, EV_ADD, 0, 0, socket);
        ret = kevent(object->epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0)
        {
            swSysWarn("kqueue->set(%d, SW_EVENT_WRITE) failed", fd);
            return SW_ERR;
        }
    }
    else
    {
        EV_SET(&e, fd, EVFILT_WRITE, EV_DELETE, 0, 0, socket);
        ret = kevent(object->epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0)
        {
            swSysWarn("kqueue->del(%d, SW_EVENT_WRITE) failed", fd);
            return SW_ERR;
        }
    }

    swReactor_set(reactor, socket, events);
    swTraceLog(SW_TRACE_EVENT, "[THREAD #%d]EP=%d|FD=%d, events=%d", SwooleTG.id, object->epfd, fd, socket->events);

    return SW_OK;
}

static int swReactorKqueue_del(swReactor *reactor, swSocket *socket)
{
    swReactorKqueue *object = reactor->object;
    struct kevent e;
    int ret;
    int fd = socket->fd;

    if (socket->events & SW_EVENT_READ)
    {
        EV_SET(&e, fd, EVFILT_READ, EV_DELETE, 0, 0, socket);
        ret = kevent(object->epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0)
        {
            swSysWarn("kqueue->del(%d, SW_EVENT_READ) failed", fd);
            return SW_ERR;
        }
    }

    if (socket->events & SW_EVENT_WRITE)
    {
        EV_SET(&e, fd, EVFILT_WRITE, EV_DELETE, 0, 0, socket);
        ret = kevent(object->epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0)
        {
            swSysWarn("kqueue->del(%d, SW_EVENT_WRITE) failed", fd);
            return SW_ERR;
        }
    }

    swReactor_del(reactor, socket);
    swTraceLog(SW_TRACE_EVENT, "[THREAD #%d]EP=%d|FD=%d", SwooleTG.id, object->epfd, fd);

    return SW_OK;
}

static int swReactorKqueue_wait(swReactor *reactor, struct timeval *timeo)
{
    swEvent event;
    swReactorKqueue *object = (swReactorKqueue *) reactor->object;
    swReactor_handler handler;

    int i, n;
    struct timespec t = {0};
    struct timespec *t_ptr;

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
        if (reactor->onBegin != NULL)
        {
            reactor->onBegin(reactor);
        }
        if (reactor->timeout_msec > 0)
        {
            t.tv_sec = reactor->timeout_msec / 1000;
            t.tv_nsec = (reactor->timeout_msec - t.tv_sec * 1000) * 1000 * 1000;
            t_ptr = &t;
        }
        else if (reactor->defer_tasks)
        {
            t.tv_sec = 0;
            t.tv_nsec = 0;
            t_ptr = &t;
        }
        else
        {
            t_ptr = NULL;
        }

        n = kevent(object->epfd, NULL, 0, object->events, object->event_max, t_ptr);
        if (n < 0)
        {
            if (swReactor_error(reactor) < 0)
            {
                swWarn("kqueue[#%d], epfd=%d", reactor->id, object->epfd);
                return SW_ERR;
            }
            else
            {
                goto _continue;
            }
        }
        else if (n == 0)
        {
            if (reactor->onTimeout)
            {
                reactor->onTimeout(reactor);
            }
            SW_REACTOR_CONTINUE;
        }

        swTraceLog(SW_TRACE_EVENT, "n %d events", n);

        for (i = 0; i < n; i++)
        {
            struct kevent *kevent = &object->events[i];
            void *udata = (void *) kevent->udata;
            if (!udata)
            {
                continue;
            }
            switch (kevent->filter)
            {
            case EVFILT_READ:
            case EVFILT_WRITE:
            {
                if (swReactorKqueue_fetch_event(reactor, &event, udata))
                {
                    handler = swReactor_get_handler(
                        reactor,
                        kevent->filter == EVFILT_READ ? SW_EVENT_READ : SW_EVENT_WRITE,
                        event.type
                    );
                    if (sw_unlikely(handler(reactor, &event) < 0))
                    {
                        swSysWarn(
                            "kqueue event %s socket#%d handler failed",
                            kevent->filter == EVFILT_READ ? "read" : "write",
                            event.fd
                        );
                    }
                    swReactorKqueue_del_once_socket(reactor, event.socket);
                }
                break;
            }
            case EVFILT_SIGNAL:
            {
                struct
                {
                    swSignalHandler handler;
                    uint16_t signo;
                    uint16_t active;
                } *sw_signal = udata;

                if (sw_signal->active)
                {
                    if (sw_signal->handler)
                    {
                        sw_signal->handler(sw_signal->signo);
                    }
                    else
                    {
                        swoole_error_log(
                            SW_LOG_WARNING, SW_ERROR_UNREGISTERED_SIGNAL,
                            SW_UNREGISTERED_SIGNAL_FMT,
                            swSignal_str(sw_signal->signo)
                        );
                    }
                }
                break;
            }
            default:
                swWarn("unknown event filter[%d]", kevent->filter);
                break;
            }
        }

        _continue:
        if (reactor->onFinish)
        {
            reactor->onFinish(reactor);
        }
        SW_REACTOR_CONTINUE;
    }
    return 0;
}
#endif
