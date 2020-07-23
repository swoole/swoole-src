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
#include "swoole_socket.h"

#include <list>
#include <map>

enum swReactor_end_callback {
    SW_REACTOR_PRIORITY_TIMER = 0,
    SW_REACTOR_PRIORITY_DEFER_TASK,
    SW_REACTOR_PRIORITY_IDLE_TASK,
    SW_REACTOR_PRIORITY_SIGNAL_CALLBACK,
    SW_REACTOR_PRIORITY_TRY_EXIT,
    SW_REACTOR_PRIORITY_MALLOC_TRIM,
};

enum swReactor_exit_condition {
    SW_REACTOR_EXIT_CONDITION_TIMER = 0,
    SW_REACTOR_EXIT_CONDITION_DEFER_TASK,
    SW_REACTOR_EXIT_CONDITION_WAIT_PID,
    SW_REACTOR_EXIT_CONDITION_CO_SIGNAL_LISTENER,
    SW_REACTOR_EXIT_CONDITION_SIGNAL_LISTENER,
    SW_REACTOR_EXIT_CONDITION_AIO_TASK,
    SW_REACTOR_EXIT_CONDITION_SIGNALFD,
    SW_REACTOR_EXIT_CONDITION_USER_BEFORE_DEFAULT,
    SW_REACTOR_EXIT_CONDITION_DEFAULT = 999,
    SW_REACTOR_EXIT_CONDITION_USER_AFTER_DEFAULT,

};

namespace swoole {

struct swDefer_callback {
    struct _swDefer_callback *next, *prev;
    swCallback callback;
    void *data;
};

struct Callback {
    swCallback fn_;
    void *private_data_;

    Callback(swCallback fn, void *private_data) : fn_(fn), private_data_(private_data) {}
};

class CallbackManager {
  public:
    inline void append(swCallback fn, void *private_data) { list_.emplace_back(fn, private_data); }
    inline void prepend(swCallback fn, void *private_data) { list_.emplace_front(fn, private_data); }
    inline void execute() {
        while (!list_.empty()) {
            std::pair<swCallback, void *> task = list_.front();
            list_.pop_front();
            task.first(task.second);
        }
    }

  protected:
    std::list<std::pair<swCallback, void *>> list_;
};

class Reactor {
  public:
    void *object = nullptr;
    void *ptr = nullptr;

    /**
     * last signal number
     */
    int singal_no = 0;

    uint32_t event_num = 0;
    uint32_t max_event_num = 0;

    bool running = false;
    bool start = false;
    bool once = false;
    bool wait_exit = false;
    bool destroyed = false;
    /**
     * callback signal
     */
    bool check_signalfd = false;
    /**
     * reactor->wait timeout (millisecond) or -1
     */
    int32_t timeout_msec = 0;

    uint16_t id = 0;

    uint32_t max_socket = 0;

#ifdef SW_USE_MALLOC_TRIM
    time_t last_malloc_trim_time = 0;
#endif

    swReactor_handler read_handler[SW_MAX_FDTYPE] = {};
    swReactor_handler write_handler[SW_MAX_FDTYPE] = {};
    swReactor_handler error_handler[SW_MAX_FDTYPE] = {};

    swReactor_handler default_write_handler = nullptr;
    swReactor_handler default_error_handler = nullptr;

    int (*add)(Reactor *reactor, swSocket *socket, int events) = nullptr;
    int (*set)(Reactor *reactor, swSocket *socket, int events) = nullptr;
    int (*del)(Reactor *reactor, swSocket *socket) = nullptr;
    int (*wait)(Reactor *reactor, struct timeval *) = nullptr;
    void (*free)(Reactor *) = nullptr;

    CallbackManager *defer_tasks = nullptr;
    CallbackManager destroy_callbacks;

    swDefer_callback idle_task;
    swDefer_callback future_task;

    std::function<void(Reactor *)> onBegin;

    int (*write)(Reactor *reactor, swSocket *socket, const void *buf, int n) = nullptr;
    int (*close)(Reactor *reactor, swSocket *socket) = nullptr;

  private:
    std::map<int, std::function<void(Reactor *)>> end_callbacks;
    std::map<int, std::function<bool(Reactor *, int &)>> exit_conditions;

  public:
    Reactor(int max_event = SW_REACTOR_MAXEVENTS);
    ~Reactor();
    bool if_exit();
    void defer(swCallback cb, void *data = nullptr);
    void set_end_callback(enum swReactor_end_callback id, const std::function<void(Reactor *)> &fn);
    void set_exit_condition(enum swReactor_exit_condition id, const std::function<bool(Reactor *, int &)> &fn);
    inline size_t remove_exit_condition(enum swReactor_exit_condition id) { return exit_conditions.erase(id); }
    inline bool isset_exit_condition(enum swReactor_exit_condition id) {
        return exit_conditions.find(id) != exit_conditions.end();
    }
    inline bool isset_handler(int fdtype) { return read_handler[fdtype] != nullptr; }
    int set_handler(int _fdtype, swReactor_handler handler);
    void add_destroy_callback(swCallback cb, void *data = nullptr);
    void execute_end_callbacks(bool timedout = false);
    int drain_write_buffer(swSocket *socket);

    inline int add_event(swSocket *_socket, enum swEvent_type event_type) {
        if (!(_socket->events & event_type)) {
            return set(this, _socket, _socket->events | event_type);
        }
        return SW_OK;
    }

    inline int del_event(swSocket *_socket, enum swEvent_type event_type) {
        if (_socket->events & event_type) {
            return set(this, _socket, _socket->events & (~event_type));
        }
        return SW_OK;
    }

    inline int remove_read_event(swSocket *_socket) {
        if (_socket->events & SW_EVENT_WRITE) {
            _socket->events &= (~SW_EVENT_READ);
            return set(this, _socket, _socket->events);
        } else {
            return del(this, _socket);
        }
    }

    inline int remove_write_event(swSocket *_socket) {
        if (_socket->events & SW_EVENT_READ) {
            _socket->events &= (~SW_EVENT_WRITE);
            return set(this, _socket, _socket->events);
        } else {
            return del(this, _socket);
        }
    }

    inline int add_read_event(swSocket *_socket) {
        if (_socket->events & SW_EVENT_WRITE) {
            _socket->events |= SW_EVENT_READ;
            return set(this, _socket, _socket->events);
        } else {
            return add(this, _socket, SW_EVENT_READ);
        }
    }

    inline int add_write_event(swSocket *_socket) {
        if (_socket->events & SW_EVENT_READ) {
            _socket->events |= SW_EVENT_WRITE;
            return set(this, _socket, _socket->events);
        } else {
            return add(this, _socket, SW_EVENT_WRITE);
        }
    }

    inline bool is_exists(swSocket *_socket) {
        return !_socket->removed && _socket->events;
    }

    inline int get_timeout_msec() {
        return defer_tasks == nullptr ? timeout_msec : 0;
    }

    inline swReactor_handler get_handler(enum swEvent_type event_type, enum swFd_type fdtype) {
        switch (event_type) {
        case SW_EVENT_READ:
            return read_handler[fdtype];
        case SW_EVENT_WRITE:
            return write_handler[fdtype] ? write_handler[fdtype] : default_write_handler;
        case SW_EVENT_ERROR:
            return error_handler[fdtype] ? error_handler[fdtype] : default_error_handler;
        default:
            abort();
            break;
        }
        return nullptr;
    }

    inline void before_wait() {
        start = running = true;
    }

    inline int trigger_close_event(swEvent *event) {
        return default_error_handler(this, event);
    }

    inline void set_wait_exit(bool enable) {
        wait_exit = enable;
    }

    inline void _add(swSocket *_socket, int events) {
        _socket->events = events;
        _socket->removed = 0;
        event_num++;
    }

    inline void _set(swSocket *_socket, int events) {
        _socket->events = events;
    }

    inline void _del(swSocket *_socket) {
        _socket->events = 0;
        _socket->removed = 1;
        event_num--;
    }

    void activate_future_task();
};
}  // namespace swoole

static sw_inline int swReactor_error(swReactor *reactor) {
    switch (errno) {
    case EINTR:
        return SW_OK;
    }
    return SW_ERR;
}

static sw_inline int swReactor_event_read(int fdtype) {
    return (fdtype < SW_EVENT_DEAULT) || (fdtype & SW_EVENT_READ);
}

static sw_inline int swReactor_event_write(int fdtype) {
    return fdtype & SW_EVENT_WRITE;
}

static sw_inline int swReactor_event_error(int fdtype) {
    return fdtype & SW_EVENT_ERROR;
}

static sw_inline enum swFd_type swReactor_fdtype(int flags) {
    return (enum swFd_type)(flags & (~SW_EVENT_READ) & (~SW_EVENT_WRITE) & (~SW_EVENT_ERROR) & (~SW_EVENT_ONCE));
}

static sw_inline int swReactor_events(int flags) {
    int events = 0;
    if (swReactor_event_read(flags)) {
        events |= SW_EVENT_READ;
    }
    if (swReactor_event_write(flags)) {
        events |= SW_EVENT_WRITE;
    }
    if (swReactor_event_error(flags)) {
        events |= SW_EVENT_ERROR;
    }
    if (flags & SW_EVENT_ONCE) {
        events |= SW_EVENT_ONCE;
    }
    return events;
}

#define SW_REACTOR_CONTINUE                                                                                            \
    if (reactor->once) {                                                                                               \
        break;                                                                                                         \
    } else {                                                                                                           \
        continue;                                                                                                      \
    }

int swReactor_onWrite(swReactor *reactor, swEvent *ev);
int swReactor_close(swReactor *reactor, swSocket *socket);
int swReactor_write(swReactor *reactor, swSocket *socket, const void *buf, int n);

int swReactorEpoll_create(swReactor *reactor, int max_event_num);
int swReactorPoll_create(swReactor *reactor, int max_event_num);
int swReactorKqueue_create(swReactor *reactor, int max_event_num);
int swReactorSelect_create(swReactor *reactor);
