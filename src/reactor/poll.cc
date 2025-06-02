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

#include <poll.h>

#include "swoole.h"
#include "swoole_socket.h"
#include "swoole_reactor.h"

namespace swoole {
using network::Socket;

class ReactorPoll final : public ReactorImpl {
    pollfd *events_;
    int max_events_;
    int set_events() const;

  public:
    ReactorPoll(Reactor *_reactor, int max_events);
    ~ReactorPoll() override;
    bool ready() override {
        return true;
    };
    int add(Socket *socket, int events) override;
    int set(Socket *socket, int events) override;
    int del(Socket *socket) override;
    int wait() override;
};

ReactorImpl *make_reactor_poll(Reactor *_reactor, int max_events) {
    return new ReactorPoll(_reactor, max_events);
}

ReactorPoll::ReactorPoll(Reactor *_reactor, int max_events) : ReactorImpl(_reactor) {
    events_ = new pollfd[max_events];
    max_events_ = max_events;
    reactor_->max_event_num = max_events;
}

ReactorPoll::~ReactorPoll() {
    delete[] events_;
}

int ReactorPoll::set_events() const {
    const auto sockets = reactor_->get_sockets();
    int count = 0;
    for (const auto pair : sockets) {
        const auto _socket = pair.second;
        events_[count].fd = _socket->fd;
        events_[count].events = translate_events_to_poll(_socket->events);
        events_[count].revents = 0;
        count++;
    }
    return count;
}

int ReactorPoll::add(Socket *socket, const int events) {
    if (reactor_->_exists(socket)) {
        swoole_error_log(
            SW_LOG_WARNING,
            SW_ERROR_EVENT_ADD_FAILED,
            "[Reactor#%d] failed to add events[fd=%d, fd_type=%d, events=%d], the socket#%d is already exists",
            reactor_->id,
            socket->fd,
            socket->fd_type,
            events,
            socket->fd);
        swoole_print_backtrace_on_error();
        return SW_ERR;
    }

    if (reactor_->get_event_num() == static_cast<size_t>(max_events_)) {
        swoole_error_log(
            SW_LOG_WARNING, SW_ERROR_EVENT_ADD_FAILED, "too many sockets, the max events is %d", max_events_);
        swoole_print_backtrace_on_error();
        return SW_ERR;
    }

    swoole_trace("fd=%d, events=%d", socket->fd, events);
    reactor_->_add(socket, events);

    return SW_OK;
}

int ReactorPoll::set(Socket *socket, int events) {
    if (!reactor_->_exists(socket)) {
        swoole_error_log(
            SW_LOG_WARNING,
            SW_ERROR_SOCKET_NOT_EXISTS,
            "[Reactor#%d] failed to set events[fd=%d, fd_type=%d, events=%d], the socket#%d has already been removed",
            reactor_->id,
            socket->fd,
            socket->fd_type,
            events,
            socket->fd);
        swoole_print_backtrace_on_error();
        return SW_ERR;
    }

    swoole_trace("fd=%d, events=%d", socket->fd, events);
    reactor_->_set(socket, events);

    return SW_OK;
}

int ReactorPoll::del(Socket *socket) {
    if (socket->removed) {
        swoole_error_log(
            SW_LOG_WARNING,
            SW_ERROR_SOCKET_NOT_EXISTS,
            "[Reactor#%d] failed to delete events[fd=%d, fd_type=%d], the socket#%d has already been removed",
            reactor_->id,
            socket->fd,
            socket->fd_type,
            socket->fd);
        swoole_print_backtrace_on_error();
        return SW_ERR;
    }

    if (!reactor_->_exists(socket)) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_SOCKET_NOT_EXISTS,
                         "[Reactor#%d] failed to delete events[fd=%d, fd_type=%d], the socket#%d is not exists",
                         reactor_->id,
                         socket->fd,
                         socket->fd_type,
                         socket->fd);
        swoole_print_backtrace_on_error();
        return SW_ERR;
    }

    reactor_->_del(socket);
    return SW_OK;
}

int ReactorPoll::wait() {
    Event event;
    ReactorHandler handler;

    reactor_->before_wait();

    while (reactor_->running) {
        reactor_->execute_begin_callback();
        const int event_num = set_events();
        int ret = poll(events_, event_num, reactor_->get_timeout_msec());
        if (ret < 0) {
            if (!reactor_->catch_error()) {
                swoole_sys_warning("[Reactor#%d] poll(nfds=%d, timeout=%d) failed",
                                   reactor_->id,
                                   event_num,
                                   reactor_->get_timeout_msec());
                break;
            }
        } else if (ret == 0) {
            reactor_->execute_end_callbacks(true);
            SW_REACTOR_CONTINUE;
        } else {
            for (int i = 0; i < event_num; i++) {
                event.socket = reactor_->get_socket(events_[i].fd);
                event.fd = events_[i].fd;
                event.reactor_id = reactor_->id;
                event.type = event.socket->fd_type;

                if (events_[i].revents & (POLLHUP | POLLERR)) {
                    event.socket->event_hup = 1;
                }

                swoole_trace("Event: fd=%d|reactor_id=%d|type=%d", event.fd, reactor_->id, event.type);
                // in
                if ((events_[i].revents & POLLIN) && !event.socket->removed) {
                    handler = reactor_->get_handler(event.type, SW_EVENT_READ);
                    ret = handler(reactor_, &event);
                    if (ret < 0) {
                        swoole_sys_warning("POLLIN handle failed. fd=%d", event.fd);
                        swoole_print_backtrace_on_error();
                    }
                }
                // out
                if ((events_[i].revents & POLLOUT) && !event.socket->removed) {
                    handler = reactor_->get_handler(event.type, SW_EVENT_WRITE);
                    ret = handler(reactor_, &event);
                    if (ret < 0) {
                        swoole_sys_warning("POLLOUT handle failed. fd=%d", event.fd);
                        swoole_print_backtrace_on_error();
                    }
                }
                // error
                if ((events_[i].revents & (POLLHUP | POLLERR)) && !event.socket->removed) {
                    // ignore ERR and HUP, because event is already processed at IN and OUT handler.
                    if ((events_[i].revents & POLLIN) || (events_[i].revents & POLLOUT)) {
                        continue;
                    }
                    handler = reactor_->get_error_handler(event.type);
                    ret = handler(reactor_, &event);
                    if (ret < 0) {
                        swoole_sys_warning("POLLERR handle failed. fd=%d", event.fd);
                        swoole_print_backtrace_on_error();
                    }
                }
                if (!event.socket->removed && (event.socket->events & SW_EVENT_ONCE)) {
                    del(event.socket);
                }
            }
        }
        reactor_->execute_end_callbacks(false);
        SW_REACTOR_CONTINUE;
    }
    return SW_OK;
}

int16_t translate_events_to_poll(int events) {
    int16_t poll_events = 0;

    if (events & SW_EVENT_READ) {
        poll_events |= POLLIN;
    }
    if (events & SW_EVENT_WRITE) {
        poll_events |= POLLOUT;
    }

    return poll_events;
}

int translate_events_from_poll(int16_t events) {
    int sw_events = 0;

    if (events & POLLIN) {
        sw_events |= SW_EVENT_READ;
    }
    if (events & POLLOUT) {
        sw_events |= SW_EVENT_WRITE;
    }
    // ignore ERR and HUP, because event is already processed at IN and OUT handler.
    if ((((events & POLLERR) || (events & POLLHUP)) && !((events & POLLIN) || (events & POLLOUT)))) {
        sw_events |= SW_EVENT_ERROR;
    }

    return sw_events;
}
}  // namespace swoole
