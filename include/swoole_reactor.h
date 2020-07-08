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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"

namespace swoole {

class Reactor
{
public:
    void *object;
    void *ptr;  //reserve

    /**
     * last signal number
     */
    int singal_no;

    uint32_t event_num;
    uint32_t max_event_num;
    uint16_t signal_listener_num;
    uint16_t co_signal_listener_num;

    bool running;
    bool start;
    bool once;
    bool wait_exit;
    /**
     * callback signal
     */
    bool check_signalfd;
    /**
     * reactor->wait timeout (millisecond) or -1
     */
    int32_t timeout_msec;

    uint16_t id; //Reactor ID
    uint16_t flag; //flag

    uint32_t max_socket;

#ifdef SW_USE_MALLOC_TRIM
    time_t last_malloc_trim_time;
#endif

    swReactor_handler read_handler[SW_MAX_FDTYPE];
    swReactor_handler write_handler[SW_MAX_FDTYPE];
    swReactor_handler error_handler[SW_MAX_FDTYPE];

    swReactor_handler default_write_handler;
    swReactor_handler default_error_handler;

    int (*add)(Reactor *reactor, swSocket *socket, int events);
    int (*set)(Reactor *reactor, swSocket *socket, int events);
    int (*del)(Reactor *reactor, swSocket *socket);
    int (*wait)(Reactor *reactor, struct timeval *);
    void (*free)(Reactor *);

    CallbackManager *defer_tasks;
    CallbackManager destroy_callbacks;

    swDefer_callback idle_task;
    swDefer_callback future_task;

    std::map<int, swCallback> end_callbacks;

    void (*onTimeout)(Reactor *reactor);
    void (*onFinish)(Reactor *reactor);
    void (*onBegin)(Reactor *reactor);

    int (*is_empty)(Reactor *reactor);
    int (*can_exit)(Reactor *reactor);

    int (*write)(Reactor *reactor, swSocket *socket, const void *buf, int n);
    int (*close)(Reactor *reactor, swSocket *socket);

public:
    Reactor(int max_event = SW_REACTOR_MAXEVENTS);
    ~Reactor();
    void defer(swCallback cb, void *data = nullptr);
    void add_end_callback(int priority, swCallback cb);
    void add_destroy_callback(swCallback cb, void *data = nullptr);
};
}

static sw_inline int swReactor_error(swReactor *reactor)
{
    switch (errno)
    {
    case EINTR:
        return SW_OK;
    }
    return SW_ERR;
}

static sw_inline int swReactor_event_read(int fdtype)
{
    return (fdtype < SW_EVENT_DEAULT) || (fdtype & SW_EVENT_READ);
}

static sw_inline int swReactor_event_write(int fdtype)
{
    return fdtype & SW_EVENT_WRITE;
}

static sw_inline int swReactor_event_error(int fdtype)
{
    return fdtype & SW_EVENT_ERROR;
}

static sw_inline enum swFd_type swReactor_fdtype(int flags)
{
    return (enum swFd_type) (flags & (~SW_EVENT_READ) & (~SW_EVENT_WRITE) & (~SW_EVENT_ERROR) & (~SW_EVENT_ONCE));
}

static sw_inline int swReactor_events(int flags)
{
    int events = 0;
    if (swReactor_event_read(flags))
    {
        events |= SW_EVENT_READ;
    }
    if (swReactor_event_write(flags))
    {
        events |= SW_EVENT_WRITE;
    }
    if (swReactor_event_error(flags))
    {
        events |= SW_EVENT_ERROR;
    }
    if (flags & SW_EVENT_ONCE)
    {
        events |= SW_EVENT_ONCE;
    }
    return events;
}

static inline void swReactor_before_wait(swReactor *reactor)
{
    reactor->running = 1;
    reactor->start = 1;
}

static inline void swReactor_wait_exit(swReactor *reactor, int value)
{
    reactor->wait_exit = value;
}

#define SW_REACTOR_CONTINUE   if (reactor->once) {break;} else {continue;}

int swReactor_empty(swReactor *reactor);

static sw_inline int swReactor_isset_handler(swReactor *reactor, int fdtype)
{
    return reactor->read_handler[fdtype] != NULL;
}

static sw_inline void swReactor_add(swReactor *reactor, swSocket *_socket, int events)
{
    _socket->events = events;
    _socket->removed = 0;
    reactor->event_num++;
}

static sw_inline void swReactor_set(swReactor *reactor, swSocket *_socket, int events)
{
    _socket->events = events;
}

static sw_inline void swReactor_del(swReactor *reactor, swSocket *_socket)
{
    _socket->events = 0;
    _socket->removed = 1;
    reactor->event_num--;
}

static sw_inline int swReactor_exists(swReactor *reactor, swSocket *_socket)
{
    return !_socket->removed && _socket->events;
}

static sw_inline int swReactor_get_timeout_msec(swReactor *reactor)
{
    return reactor->defer_tasks == nullptr ? reactor->timeout_msec : 0;
}

int swReactor_onWrite(swReactor *reactor, swEvent *ev);
int swReactor_close(swReactor *reactor, swSocket *socket);
int swReactor_write(swReactor *reactor, swSocket *socket, const void *buf, int n);
int swReactor_wait_write_buffer(swReactor *reactor, swSocket *socket);
void swReactor_activate_future_task(swReactor *reactor);

static sw_inline int swReactor_add_event(swReactor *reactor, swSocket *_socket, enum swEvent_type event_type)
{
    if (!(_socket->events & event_type))
    {
        return reactor->set(reactor, _socket, _socket->events | event_type);
    }
    return SW_OK;
}

static sw_inline int swReactor_del_event(swReactor *reactor, swSocket *_socket, enum swEvent_type event_type)
{
    if (_socket->events & event_type)
    {
        return reactor->set(reactor, _socket, _socket->events & (~event_type));
    }
    return SW_OK;
}

static sw_inline int swReactor_remove_read_event(swReactor *reactor, swSocket *_socket)
{
    if (_socket->events & SW_EVENT_WRITE)
    {
        _socket->events &= (~SW_EVENT_READ);
        return reactor->set(reactor, _socket, _socket->events);
    }
    else
    {
        return reactor->del(reactor, _socket);
    }
}

static sw_inline int swReactor_remove_write_event(swReactor *reactor, swSocket *_socket)
{
    if (_socket->events & SW_EVENT_READ)
    {
        _socket->events &= (~SW_EVENT_WRITE);
        return reactor->set(reactor, _socket, _socket->events);
    }
    else
    {
        return reactor->del(reactor, _socket);
    }
}

static sw_inline int swReactor_add_read_event(swReactor *reactor, swSocket *_socket)
{
    if (_socket->events & SW_EVENT_WRITE)
    {
        _socket->events |= SW_EVENT_READ;
        return reactor->set(reactor, _socket, _socket->events);
    }
    else
    {
        return reactor->add(reactor, _socket, SW_EVENT_READ);
    }
}

static sw_inline int swReactor_add_write_event(swReactor *reactor, swSocket *_socket)
{
    if (_socket->events & SW_EVENT_READ)
    {
        _socket->events |= SW_EVENT_WRITE;
        return reactor->set(reactor, _socket, _socket->events);
    }
    else
    {
        return reactor->add(reactor, _socket, SW_EVENT_WRITE);;
    }
}

static sw_inline swReactor_handler swReactor_get_handler(swReactor *reactor, enum swEvent_type event_type, enum swFd_type fdtype)
{
    switch(event_type)
    {
    case SW_EVENT_READ:
        return reactor->read_handler[fdtype];
    case SW_EVENT_WRITE:
        return (reactor->write_handler[fdtype] != NULL) ? reactor->write_handler[fdtype] : reactor->default_write_handler;
    case SW_EVENT_ERROR:
        return (reactor->error_handler[fdtype] != NULL) ? reactor->error_handler[fdtype] : reactor->default_error_handler;
    default:
        abort();
        break;
    }
    return NULL;
}

int swReactor_set_handler(swReactor *reactor, int fdtype, swReactor_handler);

static sw_inline int swReactor_trigger_close_event(swReactor *reactor, swEvent *event)
{
    return reactor->default_error_handler(reactor, event);
}



int swReactorEpoll_create(swReactor *reactor, int max_event_num);
int swReactorPoll_create(swReactor *reactor, int max_event_num);
int swReactorKqueue_create(swReactor *reactor, int max_event_num);
int swReactorSelect_create(swReactor *reactor);
