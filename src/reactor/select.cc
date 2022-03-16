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
#include <unordered_map>

#include <sys/select.h>

namespace swoole {

using network::Socket;

class ReactorSelect : public ReactorImpl {
    fd_set rfds;
    fd_set wfds;
    fd_set efds;
    std::unordered_map<int, Socket *> fds;
    int maxfd;

  public:
    ReactorSelect(Reactor *reactor);
    ~ReactorSelect() {}
    bool ready() override {
        return true;
    }
    int add(Socket *socket, int events) override;
    int set(Socket *socket, int events) override;
    int del(Socket *socket) override;
    int wait(struct timeval *) override;
};

#define SW_FD_SET(fd, set)                                                                                             \
    do {                                                                                                               \
        if (fd < FD_SETSIZE) FD_SET(fd, set);                                                                          \
    } while (0)

#define SW_FD_CLR(fd, set)                                                                                             \
    do {                                                                                                               \
        if (fd < FD_SETSIZE) FD_CLR(fd, set);                                                                          \
    } while (0)

#define SW_FD_ISSET(fd, set) ((fd < FD_SETSIZE) && FD_ISSET(fd, set))

ReactorImpl *make_reactor_select(Reactor *_reactor) {
    return new ReactorSelect(_reactor);
}

ReactorSelect::ReactorSelect(Reactor *reactor) : ReactorImpl(reactor) {
    maxfd = 0;
}

int ReactorSelect::add(Socket *socket, int events) {
    int fd = socket->fd;
    if (fd > FD_SETSIZE) {
        swoole_warning("max fd value is FD_SETSIZE(%d).\n", FD_SETSIZE);
        return SW_ERR;
    }

    reactor_->_add(socket, events);
    fds.emplace(fd, socket);
    if (fd > maxfd) {
        maxfd = fd;
    }

    return SW_OK;
}

int ReactorSelect::del(Socket *socket) {
    if (socket->removed) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_EVENT_SOCKET_REMOVED,
                         "failed to delete event[%d], it has already been removed",
                         socket->fd);
        return SW_ERR;
    }
    int fd = socket->fd;
    if (fds.erase(fd) == 0) {
        swoole_warning("swReactorSelect: fd[%d] not found", fd);
        return SW_ERR;
    }
    SW_FD_CLR(fd, &rfds);
    SW_FD_CLR(fd, &wfds);
    SW_FD_CLR(fd, &efds);
    reactor_->_del(socket);
    return SW_OK;
}

int ReactorSelect::set(Socket *socket, int events) {
    auto i = fds.find(socket->fd);
    if (i == fds.end()) {
        swoole_warning("swReactorSelect: sock[%d] not found", socket->fd);
        return SW_ERR;
    }
    reactor_->_set(socket, events);
    return SW_OK;
}

int ReactorSelect::wait(struct timeval *timeo) {
    Event event;
    ReactorHandler handler;
    struct timeval timeout;
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
        FD_ZERO(&(rfds));
        FD_ZERO(&(wfds));
        FD_ZERO(&(efds));

        if (reactor_->onBegin != nullptr) {
            reactor_->onBegin(reactor_);
        }

        for (auto i = fds.begin(); i != fds.end(); i++) {
            int fd = i->first;
            int events = i->second->events;
            if (Reactor::isset_read_event(events)) {
                SW_FD_SET(fd, &(rfds));
            }
            if (Reactor::isset_write_event(events)) {
                SW_FD_SET(fd, &(wfds));
            }
            if (Reactor::isset_error_event(events)) {
                SW_FD_SET(fd, &(efds));
            }
        }

        if (reactor_->timeout_msec < 0) {
            timeout.tv_sec = UINT_MAX;
            timeout.tv_usec = 0;
        } else if (reactor_->defer_tasks) {
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
        } else {
            timeout.tv_sec = reactor_->timeout_msec / 1000;
            timeout.tv_usec = reactor_->timeout_msec - timeout.tv_sec * 1000;
        }

        ret = select(maxfd + 1, &(rfds), &(wfds), &(efds), &timeout);
        if (ret < 0) {
            if (!reactor_->catch_error()) {
                swoole_sys_warning("select error");
                break;
            } else {
                goto _continue;
            }
        } else if (ret == 0) {
            reactor_->execute_end_callbacks(true);
            SW_REACTOR_CONTINUE;
        } else {
            for (int fd = 0; fd <= maxfd; fd++) {
                auto i = fds.find(fd);
                if (i == fds.end()) {
                    continue;
                }
                event.socket = i->second;
                event.fd = event.socket->fd;
                event.reactor_id = reactor_->id;
                event.type = event.socket->fd_type;

                // read
                if (SW_FD_ISSET(event.fd, &(rfds)) && !event.socket->removed) {
                    handler = reactor_->get_handler(SW_EVENT_READ, event.type);
                    ret = handler(reactor_, &event);
                    if (ret < 0) {
                        swoole_sys_warning("[Reactor#%d] select event[type=READ, fd=%d] handler fail", reactor_->id, event.fd);
                    }
                }
                // write
                if (SW_FD_ISSET(event.fd, &(wfds)) && !event.socket->removed) {
                    handler = reactor_->get_handler(SW_EVENT_WRITE, event.type);
                    ret = handler(reactor_, &event);
                    if (ret < 0) {
                        swoole_sys_warning("[Reactor#%d] select event[type=WRITE, fd=%d] handler fail", reactor_->id, event.fd);
                    }
                }
                // error
                if (SW_FD_ISSET(event.fd, &(efds)) && !event.socket->removed) {
                    handler = reactor_->get_handler(SW_EVENT_ERROR, event.type);
                    ret = handler(reactor_, &event);
                    if (ret < 0) {
                        swoole_sys_warning("[Reactor#%d] select event[type=ERROR, fd=%d] handler fail", reactor_->id, event.fd);
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

}  // namespace swoole
