/**
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

#include "swoole_reactor.h"
#include "swoole_client.h"
#include "swoole_coroutine_socket.h"
#include "swoole_coroutine_system.h"

using swoole::Callback;
using swoole::Reactor;
using swoole::ReactorHandler;
using swoole::network::Socket;

int swoole_event_init(int flags) {
    auto *reactor = new Reactor(SW_REACTOR_MAXEVENTS);
    if (!reactor->ready()) {
        return SW_ERR;
    }

    if (flags & SW_EVENTLOOP_WAIT_EXIT) {
        reactor->wait_exit = true;
    }

    swoole::coroutine::Socket::init_reactor(reactor);
    swoole::coroutine::System::init_reactor(reactor);
    swoole::network::Client::init_reactor(reactor);

    SwooleTG.reactor = reactor;

    return SW_OK;
}

int swoole_event_add(Socket *socket, int events) {
    return SwooleTG.reactor->add(socket, events);
}

int swoole_event_add_or_update(Socket *_socket, int event) {
    if (event == SW_EVENT_READ) {
        return SwooleTG.reactor->add_read_event(_socket);
    } else if (event == SW_EVENT_WRITE) {
        return SwooleTG.reactor->add_write_event(_socket);
    } else {
        assert(0);
        return SW_ERR;
    }
}

int swoole_event_set(Socket *socket, int events) {
    return SwooleTG.reactor->set(socket, events);
}

int swoole_event_del(Socket *socket) {
    return SwooleTG.reactor->del(socket);
}

int swoole_event_wait() {
    Reactor *reactor = SwooleTG.reactor;
    int retval = 0;
    if (!reactor->wait_exit or !reactor->if_exit()) {
        retval = reactor->wait();
    }
    swoole_event_free();
    return retval;
}

int swoole_event_free() {
    if (!SwooleTG.reactor) {
        return SW_ERR;
    }
    delete SwooleTG.reactor;
    SwooleTG.reactor = nullptr;
    return SW_OK;
}

void swoole_event_defer(const Callback &cb, void *private_data) {
    SwooleTG.reactor->defer(cb, private_data);
}

ssize_t swoole_event_write(Socket *socket, const void *data, size_t len) {
    return SwooleTG.reactor->write(SwooleTG.reactor, socket, data, len);
}

ssize_t swoole_event_writev(Socket *socket, const iovec *iov, size_t iovcnt) {
    return SwooleTG.reactor->writev(SwooleTG.reactor, socket, iov, iovcnt);
}

void swoole_event_set_handler(const int fd_type, const int event, const ReactorHandler handler) {
    SwooleTG.reactor->set_handler(fd_type, event, handler);
}

bool swoole_event_isset_handler(const int fd_type, const int event) {
    return SwooleTG.reactor->isset_handler(fd_type, event);
}

bool swoole_event_is_available() {
    return SwooleTG.reactor && !SwooleTG.reactor->destroyed;
}

bool swoole_event_is_running() {
    return SwooleTG.reactor && SwooleTG.reactor->running;
}

Socket *swoole_event_get_socket(int fd) {
    return SwooleTG.reactor->get_socket(fd);
}
