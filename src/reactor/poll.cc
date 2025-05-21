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

class ReactorPoll : public ReactorImpl {
    uint32_t max_fd_num;
    Socket **fds_;
    pollfd *events_;
    bool exists(int fd) const;
    void set_events(int index, int events) const;

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
    fds_ = new Socket *[max_events];
    events_ = new pollfd[max_events];

    max_fd_num = max_events;
    reactor_->max_event_num = max_events;
}

ReactorPoll::~ReactorPoll() {
    delete[] fds_;
    delete[] events_;
}

void ReactorPoll::set_events(const int index, const int events) const {
    events_[index].events = 0;
    if (Reactor::isset_read_event(events)) {
        events_[index].events |= POLLIN;
    }
    if (Reactor::isset_write_event(events)) {
        events_[index].events |= POLLOUT;
    }
    if (Reactor::isset_error_event(events)) {
        events_[index].events |= POLLHUP;
    }
}

int ReactorPoll::add(Socket *socket, const int events) {
    int fd = socket->fd;
    if (exists(fd)) {
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

    const int cur = reactor_->get_event_num();
    if (reactor_->get_event_num() == max_fd_num) {
        swoole_error_log(
            SW_LOG_WARNING, SW_ERROR_EVENT_ADD_FAILED, "too many sockets, the max events is %d", max_fd_num);
        swoole_print_backtrace_on_error();
        return SW_ERR;
    }

    reactor_->_add(socket, events);

    swoole_trace("fd=%d, events=%d", fd, events);

    fds_[cur] = socket;
    events_[cur].fd = fd;
    set_events(cur, events);

    return SW_OK;
}

int ReactorPoll::set(Socket *socket, int events) {
    swoole_trace("fd=%d, events=%d", socket->fd, events);

    SW_LOOP_N(reactor_->get_event_num()) {
        if (events_[i].fd == socket->fd) {
            set_events(i, events);
            reactor_->_set(socket, events);
            return SW_OK;
        }
    }

    swoole_error_log(SW_LOG_WARNING,
                     SW_ERROR_SOCKET_NOT_EXISTS,
                     "[Reactor#%d] failed to set events[fd=%d, fd_type=%d, events=%d], the socket#%d is not exists",
                     reactor_->id,
                     socket->fd,
                     socket->fd_type,
                     events,
                     socket->fd);
    return SW_ERR;
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

    for (uint32_t i = 0; i < reactor_->get_event_num(); i++) {
        if (events_[i].fd == socket->fd) {
            for (; i < reactor_->get_event_num(); i++) {
                if (i == reactor_->get_event_num() - 1) {
                    fds_[i] = nullptr;
                    events_[i].fd = 0;
                    events_[i].events = 0;
                } else {
                    fds_[i] = fds_[i + 1];
                    events_[i] = events_[i + 1];
                }
            }
            reactor_->_del(socket);
            return SW_OK;
        }
    }

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

int ReactorPoll::wait() {
    Event event;
    ReactorHandler handler;

    int ret;
    reactor_->before_wait();

    while (reactor_->running) {
        reactor_->execute_begin_callback();

        ret = poll(events_, reactor_->get_event_num(), reactor_->get_timeout_msec());
        if (ret < 0) {
            if (!reactor_->catch_error()) {
                swoole_sys_warning("[Reactor#%d] poll(nfds=%zu, timeout=%d) failed",
                                   reactor_->id,
                                   reactor_->get_event_num(),
                                   reactor_->get_timeout_msec());
                break;
            } else {
                goto _continue;
            }
        } else if (ret == 0) {
            reactor_->execute_end_callbacks(true);
            SW_REACTOR_CONTINUE;
        } else {
            for (uint32_t i = 0; i < reactor_->get_event_num(); i++) {
                event.socket = fds_[i];
                event.fd = events_[i].fd;
                event.reactor_id = reactor_->id;
                event.type = event.socket->fd_type;

                if (events_[i].revents & (POLLHUP | POLLERR)) {
                    event.socket->event_hup = 1;
                }

                swoole_trace("Event: fd=%d|reactor_id=%d|type=%d", event.fd, reactor_->id, event.type);
                // in
                if ((events_[i].revents & POLLIN) && !event.socket->removed) {
                    handler = reactor_->get_handler(SW_EVENT_READ, event.type);
                    ret = handler(reactor_, &event);
                    if (ret < 0) {
                        swoole_sys_warning("POLLIN handle failed. fd=%d", event.fd);
                        swoole_print_backtrace_on_error();
                    }
                }
                // out
                if ((events_[i].revents & POLLOUT) && !event.socket->removed) {
                    handler = reactor_->get_handler(SW_EVENT_WRITE, event.type);
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
    _continue:
        reactor_->execute_end_callbacks(false);
        SW_REACTOR_CONTINUE;
    }
    return SW_OK;
}

bool ReactorPoll::exists(int fd) const {
    for (uint32_t i = 0; i < reactor_->get_event_num(); i++) {
        if (events_[i].fd == fd) {
            return true;
        }
    }
    return false;
}

}  // namespace swoole
