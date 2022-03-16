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
 +----------------------------------------------------------------------+
 */

#include "swoole.h"
#include "swoole_socket.h"
#include "swoole_reactor.h"
#include "swoole_signal.h"

#ifdef HAVE_KQUEUE

#ifdef USE_KQUEUE_IDE_HELPER
#include "helper/kqueue.h"
#else
#include <sys/event.h>
#endif

namespace swoole {

using network::Socket;

class ReactorKqueue : public ReactorImpl {
    int epfd_;
    int event_max_;
    struct kevent *events_;

    bool fetch_event(Event *event, void *udata) {
        event->socket = (Socket *) udata;
        event->fd = event->socket->fd;
        event->type = event->socket->fd_type;
        event->reactor_id = reactor_->id;

        if (event->socket->removed) {
            return false;
        }
        return true;
    }

    void del_once_socket(Socket *socket) {
        if ((socket->events & SW_EVENT_ONCE) && !socket->removed) {
            del(socket);
        }
    }

  public:
    ReactorKqueue(Reactor *reactor, int max_events);
    ~ReactorKqueue();
    bool ready() override;
    int add(Socket *socket, int events) override;
    int set(Socket *socket, int events) override;
    int del(Socket *socket) override;
    int wait(struct timeval *) override;
};

ReactorImpl *make_reactor_kqueue(Reactor *_reactor, int max_events) {
    return new ReactorKqueue(_reactor, max_events);
}

ReactorKqueue::ReactorKqueue(Reactor *reactor, int max_events) : ReactorImpl(reactor) {
    epfd_ = kqueue();
    if (epfd_ < 0) {
        swoole_warning("[swReactorKqueueCreate] kqueue_create[0] fail");
        return;
    }

    reactor_->max_event_num = max_events;
    reactor_->native_handle = epfd_;
    event_max_ = max_events;
    events_ = new struct kevent[max_events];
}

bool ReactorKqueue::ready() {
    return epfd_ >= 0;
}

ReactorKqueue::~ReactorKqueue() {
    if (epfd_ >= 0) {
        close(epfd_);
    }
    delete[] events_;
}

int ReactorKqueue::add(Socket *socket, int events) {
    struct kevent e;
    int ret;

    int fd = socket->fd;
    int fflags = 0;

#ifndef __NetBSD__
    auto sobj = socket;
#else
    auto sobj = reinterpret_cast<intptr_t>(socket);
#endif

    if (Reactor::isset_read_event(events)) {
#ifdef NOTE_EOF
        fflags = NOTE_EOF;
#endif
        EV_SET(&e, fd, EVFILT_READ, EV_ADD, fflags, 0, sobj);
        ret = ::kevent(epfd_, &e, 1, nullptr, 0, nullptr);
        if (ret < 0) {
            swoole_sys_warning(
                "add events_[fd=%d, reactor_id=%d, type=%d, events=read] failed", fd, reactor_->id, socket->fd_type);
            return SW_ERR;
        }
    }

    if (Reactor::isset_write_event(events)) {
        EV_SET(&e, fd, EVFILT_WRITE, EV_ADD, 0, 0, sobj);
        ret = ::kevent(epfd_, &e, 1, nullptr, 0, nullptr);
        if (ret < 0) {
            swoole_sys_warning(
                "add events_[fd=%d, reactor_id=%d, type=%d, events=write] failed", fd, reactor_->id, socket->fd_type);
            return SW_ERR;
        }
    }

    reactor_->_add(socket, events);
    swoole_trace_log(SW_TRACE_EVENT, "[THREAD #%d]epfd=%d, fd=%d, events=%d", SwooleTG.id, epfd_, fd, socket->events);

    return SW_OK;
}

int ReactorKqueue::set(Socket *socket, int events) {
    struct kevent e;
    int ret;

    int fd = socket->fd;
    int fflags = 0;

#ifndef __NetBSD__
    auto sobj = socket;
#else
    auto sobj = reinterpret_cast<intptr_t>(socket);
#endif

    if (Reactor::isset_read_event(events)) {
#ifdef NOTE_EOF
        fflags = NOTE_EOF;
#endif
        EV_SET(&e, fd, EVFILT_READ, EV_ADD, fflags, 0, sobj);
        ret = ::kevent(epfd_, &e, 1, nullptr, 0, nullptr);
        if (ret < 0) {
            swoole_sys_warning("kqueue->set(%d, SW_EVENT_READ) failed", fd);
            return SW_ERR;
        }
    } else {
        EV_SET(&e, fd, EVFILT_READ, EV_DELETE, 0, 0, sobj);
        ret = ::kevent(epfd_, &e, 1, nullptr, 0, nullptr);
        if (ret < 0) {
            swoole_sys_warning("kqueue->del(%d, SW_EVENT_READ) failed", fd);
            return SW_ERR;
        }
    }

    if (Reactor::isset_write_event(events)) {
        EV_SET(&e, fd, EVFILT_WRITE, EV_ADD, 0, 0, sobj);
        ret = ::kevent(epfd_, &e, 1, nullptr, 0, nullptr);
        if (ret < 0) {
            swoole_sys_warning("kqueue->set(%d, SW_EVENT_WRITE) failed", fd);
            return SW_ERR;
        }
    } else {
        EV_SET(&e, fd, EVFILT_WRITE, EV_DELETE, 0, 0, sobj);
        ret = ::kevent(epfd_, &e, 1, nullptr, 0, nullptr);
        if (ret < 0) {
            swoole_sys_warning("kqueue->del(%d, SW_EVENT_WRITE) failed", fd);
            return SW_ERR;
        }
    }

    reactor_->_set(socket, events);
    swoole_trace_log(SW_TRACE_EVENT, "[THREAD #%d]epfd=%d, fd=%d, events=%d", SwooleTG.id, epfd_, fd, socket->events);

    return SW_OK;
}

int ReactorKqueue::del(Socket *socket) {
    struct kevent e;
    int ret;
    int fd = socket->fd;

#ifndef __NetBSD__
    auto sobj = socket;
#else
    auto sobj = reinterpret_cast<intptr_t>(socket);
#endif

    if (socket->removed) {
        swoole_error_log(
            SW_LOG_WARNING, SW_ERROR_EVENT_SOCKET_REMOVED, "failed to delete event[%d], has been removed", socket->fd);
        return SW_ERR;
    }

    if (socket->events & SW_EVENT_READ) {
        EV_SET(&e, fd, EVFILT_READ, EV_DELETE, 0, 0, sobj);
        ret = ::kevent(epfd_, &e, 1, nullptr, 0, nullptr);
        if (ret < 0) {
            swoole_sys_warning("kqueue->del(%d, SW_EVENT_READ) failed", fd);
            if (errno != EBADF && errno != ENOENT) {
                return SW_ERR;
            }
        }
    }

    if (socket->events & SW_EVENT_WRITE) {
        EV_SET(&e, fd, EVFILT_WRITE, EV_DELETE, 0, 0, sobj);
        ret = ::kevent(epfd_, &e, 1, nullptr, 0, nullptr);
        if (ret < 0) {
            after_removal_failure(socket);
            if (errno != EBADF && errno != ENOENT) {
                return SW_ERR;
            }
        }
    }

    reactor_->_del(socket);
    swoole_trace_log(SW_TRACE_EVENT, "[THREAD #%d]epfd=%d, fd=%d", SwooleTG.id, epfd_, fd);

    return SW_OK;
}

int ReactorKqueue::wait(struct timeval *timeo) {
    Event event;
    ReactorHandler handler;

    int i, n;
    struct timespec t = {};
    struct timespec *t_ptr;

    if (reactor_->timeout_msec == 0) {
        if (timeo == nullptr) {
            reactor_->timeout_msec = -1;
        } else {
            reactor_->timeout_msec = timeo->tv_sec * 1000 + timeo->tv_usec / 1000;
        }
    }

    reactor_->before_wait();

    while (reactor_->running) {
        if (reactor_->onBegin != nullptr) {
            reactor_->onBegin(reactor_);
        }
        if (reactor_->timeout_msec > 0) {
            t.tv_sec = reactor_->timeout_msec / 1000;
            t.tv_nsec = (reactor_->timeout_msec - t.tv_sec * 1000) * 1000 * 1000;
            t_ptr = &t;
        } else if (reactor_->defer_tasks) {
            t.tv_sec = 0;
            t.tv_nsec = 0;
            t_ptr = &t;
        } else {
            t_ptr = nullptr;
        }

        n = ::kevent(epfd_, nullptr, 0, events_, event_max_, t_ptr);
        if (n < 0) {
            if (!reactor_->catch_error()) {
                swoole_warning("kqueue[#%d], epfd=%d", reactor_->id, epfd_);
                return SW_ERR;
            } else {
                goto _continue;
            }
        } else if (n == 0) {
            reactor_->execute_end_callbacks(true);
            SW_REACTOR_CONTINUE;
        }

        swoole_trace_log(SW_TRACE_EVENT, "n %d events", n);

        for (i = 0; i < n; i++) {
            struct kevent *kevent = &events_[i];
            void *udata = (void *) kevent->udata;
            if (!udata) {
                continue;
            }
            switch (kevent->filter) {
            case EVFILT_READ:
            case EVFILT_WRITE: {
                if (fetch_event(&event, udata)) {
                    handler = reactor_->get_handler(kevent->filter == EVFILT_READ ? SW_EVENT_READ : SW_EVENT_WRITE,
                                                    event.type);
                    if (sw_unlikely(handler(reactor_, &event) < 0)) {
                        swoole_sys_warning("kqueue event %s socket#%d handler failed",
                                  kevent->filter == EVFILT_READ ? "read" : "write",
                                  event.fd);
                    }
                    del_once_socket(event.socket);
                }
                break;
            }
            case EVFILT_SIGNAL: {
                Signal *signal_data = (Signal *) udata;
                if (signal_data->activated) {
                    if (signal_data->handler) {
                        signal_data->handler(signal_data->signo);
                    } else {
                        swoole_error_log(SW_LOG_WARNING,
                                         SW_ERROR_UNREGISTERED_SIGNAL,
                                         SW_UNREGISTERED_SIGNAL_FMT,
                                         swoole_signal_to_str(signal_data->signo));
                    }
                }
                break;
            }
            default:
                swoole_warning("unknown event filter[%d]", kevent->filter);
                break;
            }
        }

    _continue:
        reactor_->execute_end_callbacks(false);
        SW_REACTOR_CONTINUE;
    }
    return 0;
}
}  // namespace swoole
#endif
