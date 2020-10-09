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
#include "swoole_socket.h"
#include "swoole_reactor.h"
#include "swoole_log.h"

#include <unordered_map>

using swoole::Reactor;
using swoole::ReactorHandler;
using swoole::network::Socket;

#define EVENT_DEBUG 0

#ifdef HAVE_EPOLL
#include <sys/epoll.h>
#ifndef EPOLLRDHUP
#error "require linux kernel version 2.6.32 or later"
#endif

#ifndef EPOLLONESHOT
#error "require linux kernel version 2.6.32 or later"
#endif

struct ReactorEpoll {
    int epfd;
    struct epoll_event *events;
};

#if EVENT_DEBUG
static thread_local std::unordered_map<int, Socket *> event_map;

Socket *swoole_event_map_get(int sockfd) {
    return event_map[sockfd];
}
#endif

static int swReactorEpoll_add(Reactor *reactor, Socket *socket, int events);
static int swReactorEpoll_set(Reactor *reactor, Socket *socket, int events);
static int swReactorEpoll_del(Reactor *reactor, Socket *_socket);
static int swReactorEpoll_wait(Reactor *reactor, struct timeval *timeo);
static void swReactorEpoll_free(Reactor *reactor);

static sw_inline int swReactorEpoll_event_set(int fdtype) {
    uint32_t flag = 0;
    if (Reactor::isset_read_event(fdtype)) {
        flag |= EPOLLIN;
    }
    if (Reactor::isset_write_event(fdtype)) {
        flag |= EPOLLOUT;
    }
    if (fdtype & SW_EVENT_ONCE) {
        flag |= EPOLLONESHOT;
    }
    if (Reactor::isset_error_event(fdtype)) {
        // flag |= (EPOLLRDHUP);
        flag |= (EPOLLRDHUP | EPOLLHUP | EPOLLERR);
    }
    return flag;
}

int swReactorEpoll_create(Reactor *reactor, int max_event_num) {
    int epfd = epoll_create(512);
    if (epfd < 0) {
        swSysWarn("epoll_create failed");
        return SW_ERR;
    }

    reactor->add = swReactorEpoll_add;
    reactor->set = swReactorEpoll_set;
    reactor->del = swReactorEpoll_del;
    reactor->wait = swReactorEpoll_wait;
    reactor->free = swReactorEpoll_free;

    ReactorEpoll *object = new ReactorEpoll();
    object->events = new struct epoll_event[max_event_num];
    object->epfd = epfd;
    reactor->max_event_num = max_event_num;
    reactor->object = object;

    return SW_OK;
}

static void swReactorEpoll_free(Reactor *reactor) {
    ReactorEpoll *object = (ReactorEpoll *) reactor->object;
    close(object->epfd);
    delete[] object->events;
    delete object;
}

static int swReactorEpoll_add(Reactor *reactor, Socket *socket, int events) {
    ReactorEpoll *object = (ReactorEpoll *) reactor->object;
    struct epoll_event e;

    e.events = swReactorEpoll_event_set(events);
    e.data.ptr = socket;

    if (epoll_ctl(object->epfd, EPOLL_CTL_ADD, socket->fd, &e) < 0) {
        swSysWarn(
            "failed to add events[fd=%d#%d, type=%d, events=%d]", socket->fd, reactor->id, socket->fd_type, events);
        return SW_ERR;
    }

#if EVENT_DEBUG
    event_map[socket->fd] = socket;
#endif

    reactor->_add(socket, events);
    swTraceLog(
        SW_TRACE_EVENT, "add events[fd=%d#%d, type=%d, events=%d]", socket->fd, reactor->id, socket->fd_type, events);

    return SW_OK;
}

static int swReactorEpoll_del(Reactor *reactor, Socket *_socket) {
    ReactorEpoll *object = (ReactorEpoll *) reactor->object;
    if (_socket->removed) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_EVENT_SOCKET_REMOVED,
                         "failed to delete events[%d], it has already been removed",
                         _socket->fd);
        return SW_ERR;
    }
    if (epoll_ctl(object->epfd, EPOLL_CTL_DEL, _socket->fd, nullptr) < 0) {
        swSysWarn("failed to delete events[fd=%d#%d, type=%d, events=%d]",
                  _socket->fd,
                  reactor->id,
                  _socket->fd_type,
                  _socket->events);
        if (errno != EBADF && errno != ENOENT) {
            return SW_ERR;
        }
    }

#if EVENT_DEBUG
    event_map.erase(_socket->fd);
#endif

    swTraceLog(SW_TRACE_REACTOR, "remove event[reactor_id=%d|fd=%d]", reactor->id, _socket->fd);
    reactor->_del(_socket);

    return SW_OK;
}

static int swReactorEpoll_set(Reactor *reactor, Socket *socket, int events) {
    ReactorEpoll *object = (ReactorEpoll *) reactor->object;
    struct epoll_event e;

    e.events = swReactorEpoll_event_set(events);
    e.data.ptr = socket;

    int ret = epoll_ctl(object->epfd, EPOLL_CTL_MOD, socket->fd, &e);
    if (ret < 0) {
        swSysWarn(
            "failed to set events[fd=%d#%d, type=%d, events=%d]", socket->fd, reactor->id, socket->fd_type, events);
        return SW_ERR;
    }

    swTraceLog(SW_TRACE_EVENT, "set event[reactor_id=%d, fd=%d, events=%d]", reactor->id, socket->fd, events);
    reactor->_set(socket, events);

    return SW_OK;
}

static int swReactorEpoll_wait(Reactor *reactor, struct timeval *timeo) {
    swEvent event;
    ReactorEpoll *object = (ReactorEpoll *) reactor->object;
    ReactorHandler handler;
    int i, n, ret;

    int reactor_id = reactor->id;
    int epoll_fd = object->epfd;
    int max_event_num = reactor->max_event_num;
    struct epoll_event *events = object->events;

    if (reactor->timeout_msec == 0) {
        if (timeo == nullptr) {
            reactor->timeout_msec = -1;
        } else {
            reactor->timeout_msec = timeo->tv_sec * 1000 + timeo->tv_usec / 1000;
        }
    }

    reactor->before_wait();

    while (reactor->running) {
        if (reactor->onBegin != nullptr) {
            reactor->onBegin(reactor);
        }
        n = epoll_wait(epoll_fd, events, max_event_num, reactor->get_timeout_msec());
        if (n < 0) {
            if (!reactor->catch_error()) {
                swSysWarn("[Reactor#%d] epoll_wait failed", reactor_id);
                return SW_ERR;
            } else {
                goto _continue;
            }
        } else if (n == 0) {
            reactor->execute_end_callbacks(true);
            SW_REACTOR_CONTINUE;
        }
        for (i = 0; i < n; i++) {
            event.reactor_id = reactor_id;
            event.socket = (Socket *) events[i].data.ptr;
            event.type = event.socket->fd_type;
            event.fd = event.socket->fd;

            // read
            if ((events[i].events & EPOLLIN) && !event.socket->removed) {
                if (events[i].events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {
                    event.socket->event_hup = 1;
                }
                handler = reactor->get_handler(SW_EVENT_READ, event.type);
                ret = handler(reactor, &event);
                if (ret < 0) {
                    swSysWarn("EPOLLIN handle failed. fd=%d", event.fd);
                }
            }
            // write
            if ((events[i].events & EPOLLOUT) && !event.socket->removed) {
                handler = reactor->get_handler(SW_EVENT_WRITE, event.type);
                ret = handler(reactor, &event);
                if (ret < 0) {
                    swSysWarn("EPOLLOUT handle failed. fd=%d", event.fd);
                }
            }
            // error
            if ((events[i].events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) && !event.socket->removed) {
                // ignore ERR and HUP, because event is already processed at IN and OUT handler.
                if ((events[i].events & EPOLLIN) || (events[i].events & EPOLLOUT)) {
                    continue;
                }
                handler = reactor->get_handler(SW_EVENT_ERROR, event.type);
                ret = handler(reactor, &event);
                if (ret < 0) {
                    swSysWarn("EPOLLERR handle failed. fd=%d", event.fd);
                }
            }
            if (!event.socket->removed && (event.socket->events & SW_EVENT_ONCE)) {
                reactor->_del(event.socket);
            }
        }

    _continue:
        reactor->execute_end_callbacks(false);
        SW_REACTOR_CONTINUE;
    }
    return 0;
}

#endif
