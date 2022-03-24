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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"
#include "swoole_socket.h"

#include <list>
#include <map>
#include <unordered_map>

namespace swoole {

struct DeferCallback {
    Callback callback;
    void *data;
};

class Reactor;

class ReactorImpl {
  protected:
    Reactor *reactor_;

  public:
    ReactorImpl(Reactor *_reactor) {
        reactor_ = _reactor;
    }
    void after_removal_failure(network::Socket *_socket);
    virtual ~ReactorImpl(){};
    virtual bool ready() = 0;
    virtual int add(network::Socket *socket, int events) = 0;
    virtual int set(network::Socket *socket, int events) = 0;
    virtual int del(network::Socket *socket) = 0;
    virtual int wait(struct timeval *) = 0;
};

class CallbackManager {
  public:
    typedef std::list<std::pair<Callback, void *>> TaskList;
    void append(Callback fn, void *private_data) {
        list_.emplace_back(fn, private_data);
    }
    void prepend(Callback fn, void *private_data) {
        list_.emplace_front(fn, private_data);
        auto t = list_.back();
    }
    void remove(TaskList::iterator iter) {
        list_.erase(iter);
    }
    void execute() {
        while (!list_.empty()) {
            std::pair<Callback, void *> task = list_.front();
            list_.pop_front();
            task.first(task.second);
        }
    }

  protected:
    TaskList list_;
};

class Reactor {
  public:
    enum Type {
        TYPE_AUTO,
        TYPE_EPOLL,
        TYPE_KQUEUE,
        TYPE_POLL,
        TYPE_SELECT,
    };

    enum EndCallback {
        PRIORITY_TIMER = 0,
        PRIORITY_DEFER_TASK,
        PRIORITY_IDLE_TASK,
        PRIORITY_SIGNAL_CALLBACK,
        PRIORITY_TRY_EXIT,
        PRIORITY_MALLOC_TRIM,
        PRIORITY_WORKER_CALLBACK,
    };

    enum ExitCondition {
        EXIT_CONDITION_TIMER = 0,
        EXIT_CONDITION_DEFER_TASK,
        EXIT_CONDITION_WAIT_PID,
        EXIT_CONDITION_CO_SIGNAL_LISTENER,
        EXIT_CONDITION_SIGNAL_LISTENER,
        EXIT_CONDITION_AIO_TASK,
        EXIT_CONDITION_SIGNALFD,
        EXIT_CONDITION_USER_BEFORE_DEFAULT,
        EXIT_CONDITION_DEFAULT = 999,
        EXIT_CONDITION_USER_AFTER_DEFAULT,
    };

    Type type_;
    void *ptr = nullptr;
    int native_handle = -1;

    /**
     * last signal number
     */
    int singal_no = 0;

    uint32_t max_event_num = 0;

    bool running = false;
    bool start = false;
    bool once = false;
    bool wait_exit = false;
    bool destroyed = false;
    bool bailout = false;
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

    ReactorHandler read_handler[SW_MAX_FDTYPE] = {};
    ReactorHandler write_handler[SW_MAX_FDTYPE] = {};
    ReactorHandler error_handler[SW_MAX_FDTYPE] = {};

    ReactorHandler default_write_handler = nullptr;
    ReactorHandler default_error_handler = nullptr;

    int add(network::Socket *socket, int events) {
        return impl->add(socket, events);
    }

    int set(network::Socket *socket, int events) {
        return impl->set(socket, events);
    }

    int del(network::Socket *socket) {
        return impl->del(socket);
    }

    int wait(struct timeval *timeout) {
        return impl->wait(timeout);
    }

    CallbackManager *defer_tasks = nullptr;
    CallbackManager destroy_callbacks;

    DeferCallback idle_task;
    DeferCallback future_task;

    std::function<void(Reactor *)> onBegin;

    ssize_t (*write)(Reactor *reactor, network::Socket *socket, const void *buf, size_t n) = nullptr;
    ssize_t (*writev)(Reactor *reactor, network::Socket *socket, const iovec *iov, size_t iovcnt) = nullptr;
    int (*close)(Reactor *reactor, network::Socket *socket) = nullptr;

  private:
    ReactorImpl *impl;
    std::map<int, std::function<void(Reactor *)>> end_callbacks;
    std::map<int, std::function<bool(Reactor *, size_t &)>> exit_conditions;
    std::unordered_map<int, network::Socket *> sockets_;

  public:
    Reactor(int max_event = SW_REACTOR_MAXEVENTS, Type _type = TYPE_AUTO);
    ~Reactor();
    bool if_exit();
    void defer(Callback cb, void *data = nullptr);
    void set_end_callback(enum EndCallback id, const std::function<void(Reactor *)> &fn);
    void set_exit_condition(enum ExitCondition id, const std::function<bool(Reactor *, size_t &)> &fn);
    bool set_handler(int _fdtype, ReactorHandler handler);
    void add_destroy_callback(Callback cb, void *data = nullptr);
    void execute_end_callbacks(bool timedout = false);
    void drain_write_buffer(network::Socket *socket);

    bool ready() {
        return running;
    }

    inline size_t remove_exit_condition(enum ExitCondition id) {
        return exit_conditions.erase(id);
    }

    inline bool isset_exit_condition(enum ExitCondition id) {
        return exit_conditions.find(id) != exit_conditions.end();
    }

    inline bool isset_handler(int fdtype) {
        return read_handler[fdtype] != nullptr;
    }

    inline int add_event(network::Socket *_socket, EventType event_type) {
        if (!(_socket->events & event_type)) {
            return set(_socket, _socket->events | event_type);
        }
        return SW_OK;
    }

    inline int del_event(network::Socket *_socket, EventType event_type) {
        if (_socket->events & event_type) {
            return set(_socket, _socket->events & (~event_type));
        }
        return SW_OK;
    }

    inline int remove_read_event(network::Socket *_socket) {
        if (_socket->events & SW_EVENT_WRITE) {
            _socket->events &= (~SW_EVENT_READ);
            return set(_socket, _socket->events);
        } else {
            return del(_socket);
        }
    }

    inline int remove_write_event(network::Socket *_socket) {
        if (_socket->events & SW_EVENT_READ) {
            _socket->events &= (~SW_EVENT_WRITE);
            return set(_socket, _socket->events);
        } else {
            return del(_socket);
        }
    }

    inline int add_read_event(network::Socket *_socket) {
        if (_socket->events & SW_EVENT_WRITE) {
            _socket->events |= SW_EVENT_READ;
            return set(_socket, _socket->events);
        } else {
            return add(_socket, SW_EVENT_READ);
        }
    }

    inline int add_write_event(network::Socket *_socket) {
        if (_socket->events & SW_EVENT_READ) {
            _socket->events |= SW_EVENT_WRITE;
            return set(_socket, _socket->events);
        } else {
            return add(_socket, SW_EVENT_WRITE);
        }
    }

    inline bool exists(network::Socket *_socket) {
        return !_socket->removed && _socket->events;
    }

    inline int get_timeout_msec() {
        return defer_tasks == nullptr ? timeout_msec : 0;
    }

    size_t get_event_num() {
        return sockets_.size();
    }

    const std::unordered_map<int, network::Socket *> &get_sockets() {
        return sockets_;
    }

    network::Socket *get_socket(int fd) {
        return sockets_[fd];
    }

    void foreach_socket(const std::function<void(int, network::Socket *)> &callback) {
        for (auto kv : sockets_) {
            callback(kv.first, kv.second);
        }
    }

    inline ReactorHandler get_handler(EventType event_type, FdType fd_type) {
        switch (event_type) {
        case SW_EVENT_READ:
            return read_handler[fd_type];
        case SW_EVENT_WRITE:
            return write_handler[fd_type] ? write_handler[fd_type] : default_write_handler;
        case SW_EVENT_ERROR:
            return error_handler[fd_type] ? error_handler[fd_type] : default_error_handler;
        default:
            abort();
            break;
        }
        return nullptr;
    }

    inline ReactorHandler get_error_handler(FdType fd_type) {
        ReactorHandler handler = get_handler(SW_EVENT_ERROR, fd_type);
        // error callback is not set, try to use readable or writable callback
        if (handler == nullptr) {
            handler = get_handler(SW_EVENT_READ, fd_type);
            if (handler == nullptr) {
                handler = get_handler(SW_EVENT_WRITE, fd_type);
            }
        }
        return handler;
    }

    inline void before_wait() {
        start = running = true;
    }

    inline int trigger_close_event(Event *event) {
        return default_error_handler(this, event);
    }

    inline void set_wait_exit(bool enable) {
        wait_exit = enable;
    }

    inline void _add(network::Socket *_socket, int events) {
        _socket->events = events;
        _socket->removed = 0;
        sockets_[_socket->fd] = _socket;
    }

    inline void _set(network::Socket *_socket, int events) {
        _socket->events = events;
    }

    inline void _del(network::Socket *_socket) {
        _socket->events = 0;
        _socket->removed = 1;
        sockets_.erase(_socket->fd);
    }

    bool catch_error() {
        switch (errno) {
        case EINTR:
            return true;
        }
        return false;
    }

    static ssize_t _write(Reactor *reactor, network::Socket *socket, const void *buf, size_t n);
    static ssize_t _writev(Reactor *reactor, network::Socket *socket, const iovec *iov, size_t iovcnt);
    static int _close(Reactor *reactor, network::Socket *socket);
    static int _writable_callback(Reactor *reactor, Event *ev);

    void activate_future_task();

    static FdType get_fd_type(int flags) {
        return (FdType)(flags & (~SW_EVENT_READ) & (~SW_EVENT_WRITE) & (~SW_EVENT_ERROR) & (~SW_EVENT_ONCE));
    }

    static bool isset_read_event(int events) {
        return (events < SW_EVENT_DEAULT) || (events & SW_EVENT_READ);
    }

    static bool isset_write_event(int events) {
        return events & SW_EVENT_WRITE;
    }

    static bool isset_error_event(int events) {
        return events & SW_EVENT_ERROR;
    }
};
}  // namespace swoole

#define SW_REACTOR_CONTINUE                                                                                            \
    if (reactor_->once) {                                                                                              \
        break;                                                                                                         \
    } else {                                                                                                           \
        continue;                                                                                                      \
    }
