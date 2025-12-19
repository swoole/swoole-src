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

#include "swoole_socket.h"
#include "swoole_reactor.h"

#ifdef HAVE_EPOLL
#include <sys/epoll.h>
#ifndef EPOLLRDHUP
#error "require linux kernel version 2.6.32 or later"
#endif

#ifndef EPOLLONESHOT
#error "require linux kernel version 2.6.32 or later"
#endif

namespace swoole {

using network::Socket;

class ReactorEpoll final : public ReactorImpl {
    int epfd_;
    epoll_event *events_ = nullptr;

  public:
    ReactorEpoll(Reactor *_reactor, int max_events);
    ~ReactorEpoll() override;
    bool ready() override;
    int add(Socket *socket, int events) override;
    int set(Socket *socket, int events) override;
    int del(Socket *_socket) override;
    int wait() override;

    static int get_events(const int fd_type) {
        int events = 0;
        if (Reactor::isset_read_event(fd_type)) {
            events |= EPOLLIN;
        }
        if (Reactor::isset_write_event(fd_type)) {
            events |= EPOLLOUT;
        }
        if (fd_type & SW_EVENT_ONCE) {
            events |= EPOLLONESHOT;
        }
        if (Reactor::isset_error_event(fd_type)) {
            events |= (EPOLLRDHUP | EPOLLHUP | EPOLLERR);
        }
        return events;
    }
};

ReactorImpl *make_reactor_epoll(Reactor *_reactor, int max_events) {
    return new ReactorEpoll(_reactor, max_events);
}

ReactorEpoll::ReactorEpoll(Reactor *_reactor, int max_events) : ReactorImpl(_reactor) {
    epfd_ = epoll_create(512);
    if (!ReactorEpoll::ready()) {
        swoole_sys_warning("epoll_create() failed");
        return;
    }

    events_ = new epoll_event[max_events];
    reactor_->max_event_num = max_events;
    reactor_->native_handle = epfd_;
}

bool ReactorEpoll::ready() {
    return epfd_ >= 0;
}

ReactorEpoll::~ReactorEpoll() {
    if (epfd_ >= 0) {
        close(epfd_);
    }
    delete[] events_;
}

int ReactorEpoll::add(Socket *socket, int events) {
    epoll_event e;

    e.events = get_events(events);
    e.data.ptr = socket;

    if (epoll_ctl(epfd_, EPOLL_CTL_ADD, socket->fd, &e) < 0) {
        swoole_sys_warning("[Reactor#%d] epoll_ctl(epfd=%d, EPOLL_CTL_ADD, fd=%d, fd_type=%d, events=%d) failed",
                           reactor_->id,
                           epfd_,
                           socket->fd,
                           socket->fd_type,
                           events);
        swoole_print_backtrace_on_error();
        return SW_ERR;
    }

    reactor_->_add(socket, events);
    swoole_trace_log(
        SW_TRACE_EVENT, "add events[fd=%d#%d, type=%d, events=%d]", socket->fd, reactor_->id, socket->fd_type, events);

    return SW_OK;
}

int ReactorEpoll::del(Socket *_socket) {
    if (_socket->removed) {
        swoole_error_log(
            SW_LOG_WARNING,
            SW_ERROR_EVENT_REMOVE_FAILED,
            "[Reactor#%d] failed to delete events[fd=%d, fd_type=%d], this socket has already been removed",
            reactor_->id,
            _socket->fd,
            _socket->fd_type);
        swoole_print_backtrace_on_error();
        return SW_ERR;
    }

    if (epoll_ctl(epfd_, EPOLL_CTL_DEL, _socket->fd, nullptr) < 0) {
        after_removal_failure(_socket);
        /**
         * Before removing it from the epoll event loop, the close operation has be executed,
         * must cleanup related resources with this socket.
         */
        if (errno != EBADF && errno != ENOENT) {
            swoole_sys_warning("[Reactor#%d] epoll_ctl(epfd=%d, EPOLL_CTL_DEL, fd=%d, fd_type=%d) failed",
                               reactor_->id,
                               epfd_,
                               _socket->fd,
                               _socket->fd_type);
            swoole_print_backtrace_on_error();
            return SW_ERR;
        }
    }

    swoole_trace_log(
        SW_TRACE_REACTOR, "remove event[reactor_id=%d|fd=%d|type=%d]", reactor_->id, _socket->fd, _socket->fd_type);
    reactor_->_del(_socket);

    return SW_OK;
}

int ReactorEpoll::set(Socket *socket, int events) {
    epoll_event e;

    e.events = get_events(events);
    e.data.ptr = socket;

    int ret = epoll_ctl(epfd_, EPOLL_CTL_MOD, socket->fd, &e);
    if (ret < 0) {
        swoole_sys_warning("[Reactor#%d] epoll_ctl(epfd=%d, EPOLL_CTL_MOD, fd=%d, fd_type=%d, events=%d) failed",
                           reactor_->id,
                           epfd_,
                           socket->fd,
                           socket->fd_type,
                           events);
        swoole_print_backtrace_on_error();
        return SW_ERR;
    }

    swoole_trace_log(SW_TRACE_EVENT, "set event[reactor_id=%d, fd=%d, events=%d]", reactor_->id, socket->fd, events);
    reactor_->_set(socket, events);

    return SW_OK;
}

int ReactorEpoll::wait() {
    Event event;
    ReactorHandler handler;
    int n, ret;

    reactor_->before_wait();

    while (reactor_->running) {
        reactor_->execute_begin_callback();

        n = epoll_wait(epfd_, events_, reactor_->max_event_num, reactor_->get_timeout_msec());
        if (n < 0) {
            if (!reactor_->catch_error()) {
                swoole_sys_warning("[Reactor#%d] epoll_wait(epfd=%d, max_events=%d, timeout=%d) failed",
                                   reactor_->id,
                                   epfd_,
                                   reactor_->max_event_num,
                                   reactor_->get_timeout_msec());
                return SW_ERR;
            } else {
#ifdef SW_USE_IOURING
                if (sw_likely(errno == EINTR && reactor_->iouring_interrupt_handler)) {
                    reactor_->iouring_interrupt_handler(reactor_);
                }
#endif
                goto _continue;
            }
        } else if (n == 0) {
            reactor_->execute_end_callbacks(true);
            SW_REACTOR_CONTINUE;
        }
        for (int i = 0; i < n; i++) {
            event.reactor_id = reactor_->id;
            event.socket = static_cast<Socket *>(events_[i].data.ptr);
            event.type = event.socket->fd_type;
            event.fd = event.socket->fd;

            if (events_[i].events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {
                event.socket->event_hup = 1;
            }
            // read
            if ((events_[i].events & EPOLLIN) && !event.socket->removed) {
                handler = reactor_->get_handler(event.type, SW_EVENT_READ);
                ret = handler(reactor_, &event);
                if (ret < 0) {
                    swoole_sys_warning("EPOLLIN handle failed [fd=%d, type=%d]", event.fd, event.type);
                }
            }
            // write
            if ((events_[i].events & EPOLLOUT) && !event.socket->removed) {
                handler = reactor_->get_handler(event.type, SW_EVENT_WRITE);
                ret = handler(reactor_, &event);
                if (ret < 0) {
                    swoole_sys_warning("EPOLLOUT handle failed [fd=%d, type=%d]", event.fd, event.type);
                }
            }
            // error
            if ((events_[i].events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) && !event.socket->removed) {
                // ignore ERR and HUP, because event is already processed at IN and OUT handler.
                if ((events_[i].events & EPOLLIN) || (events_[i].events & EPOLLOUT)) {
                    continue;
                }
                handler = reactor_->get_error_handler(event.type);
                ret = handler(reactor_, &event);
                if (ret < 0) {
                    swoole_sys_warning("EPOLLERR handle failed [fd=%d, type=%d]", event.fd, event.type);
                }
            }
            if (!event.socket->removed && (event.socket->events & SW_EVENT_ONCE)) {
                reactor_->_del(event.socket);
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
