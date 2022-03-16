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
    struct pollfd *events_;
    bool exists(int fd);

  public:
    ReactorPoll(Reactor *_reactor, int max_events);
    ~ReactorPoll();
    bool ready() override {
        return true;
    };
    int add(Socket *socket, int events) override;
    int set(Socket *socket, int events) override;
    int del(Socket *socket) override;
    int wait(struct timeval *) override;
};

ReactorImpl *make_reactor_poll(Reactor *_reactor, int max_events) {
    return new ReactorPoll(_reactor, max_events);
}

ReactorPoll::ReactorPoll(Reactor *_reactor, int max_events) : ReactorImpl(_reactor) {
    fds_ = new Socket *[max_events];
    events_ = new struct pollfd[max_events];

    max_fd_num = max_events;
    reactor_->max_event_num = max_events;
}

ReactorPoll::~ReactorPoll() {
    delete[] fds_;
    delete[] events_;
}

int ReactorPoll::add(Socket *socket, int events) {
    int fd = socket->fd;
    if (exists(fd)) {
        swoole_warning("fd#%d is already exists", fd);
        return SW_ERR;
    }

    int cur = reactor_->get_event_num();
    if (reactor_->get_event_num() == max_fd_num) {
        swoole_warning("too many connection, more than %d", max_fd_num);
        return SW_ERR;
    }

    reactor_->_add(socket, events);

    swoole_trace("fd=%d, events=%d", fd, events);

    fds_[cur] = socket;
    events_[cur].fd = fd;
    events_[cur].events = 0;

    if (Reactor::isset_read_event(events)) {
        events_[cur].events |= POLLIN;
    }
    if (Reactor::isset_write_event(events)) {
        events_[cur].events |= POLLOUT;
    }
    if (Reactor::isset_error_event(events)) {
        events_[cur].events |= POLLHUP;
    }

    return SW_OK;
}

int ReactorPoll::set(Socket *socket, int events) {
    uint32_t i;

    swoole_trace("fd=%d, events=%d", socket->fd, events);

    for (i = 0; i < reactor_->get_event_num(); i++) {
        // found
        if (events_[i].fd == socket->fd) {
            events_[i].events = 0;
            if (Reactor::isset_read_event(events)) {
                events_[i].events |= POLLIN;
            }
            if (Reactor::isset_write_event(events)) {
                events_[i].events |= POLLOUT;
            }
            // execute parent method
            reactor_->_set(socket, events);
            return SW_OK;
        }
    }

    return SW_ERR;
}

int ReactorPoll::del(Socket *socket) {
    if (socket->removed) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_EVENT_SOCKET_REMOVED,
                         "failed to delete event[%d], it has already been removed",
                         socket->fd);
        return SW_ERR;
    }

    for (uint32_t i = 0; i < reactor_->get_event_num(); i++) {
        if (events_[i].fd == socket->fd) {
            for (; i < reactor_->get_event_num(); i++) {
                if (i == reactor_->get_event_num()) {
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

    return SW_ERR;
}

int ReactorPoll::wait(struct timeval *timeo) {
    Event event;
    ReactorHandler handler;

    int ret;

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
        ret = poll(events_, reactor_->get_event_num(), reactor_->get_timeout_msec());
        if (ret < 0) {
            if (!reactor_->catch_error()) {
                swoole_sys_warning("poll error");
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
                        swoole_sys_warning("poll[POLLIN] handler failed. fd=%d", event.fd);
                    }
                }
                // out
                if ((events_[i].revents & POLLOUT) && !event.socket->removed) {
                    handler = reactor_->get_handler(SW_EVENT_WRITE, event.type);
                    ret = handler(reactor_, &event);
                    if (ret < 0) {
                        swoole_sys_warning("poll[POLLOUT] handler failed. fd=%d", event.fd);
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
                        swoole_sys_warning("poll[POLLERR] handler failed. fd=%d", event.fd);
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

bool ReactorPoll::exists(int fd) {
    for (uint32_t i = 0; i < reactor_->get_event_num(); i++) {
        if (events_[i].fd == fd) {
            return true;
        }
    }
    return false;
}

}  // namespace swoole
