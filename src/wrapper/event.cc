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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole_api.h"
#include "swoole_socket.h"
#include "swoole_reactor.h"
#include "swoole_client.h"
#include "swoole_async.h"
#include "swoole_coroutine_c_api.h"
#include "swoole_coroutine_socket.h"
#include "swoole_coroutine_system.h"

#include <mutex>
#include <thread>

using namespace swoole;

using swoole::network::Socket;

static std::mutex init_lock;

#ifdef __MACH__
Reactor *sw_reactor() {
    return SwooleTG.reactor;
}
#endif

int swoole_event_init(int flags) {
    if (!SwooleG.init) {
        std::unique_lock<std::mutex> lock(init_lock);
        swoole_init();
    }

    Reactor *reactor = new Reactor(SW_REACTOR_MAXEVENTS);
    if (flags & SW_EVENTLOOP_WAIT_EXIT) {
        reactor->wait_exit = 1;
    }

    coroutine::Socket::init_reactor(reactor);
    coroutine::System::init_reactor(reactor);
    network::Client::init_reactor(reactor);

    SwooleTG.reactor = reactor;

    return SW_OK;
}

int swoole_event_add(Socket *socket, int events) {
    return SwooleTG.reactor->add(SwooleTG.reactor, socket, events);
}

int swoole_event_set(Socket *socket, int events) {
    return SwooleTG.reactor->set(SwooleTG.reactor, socket, events);
}

int swoole_event_del(Socket *socket) {
    return SwooleTG.reactor->del(SwooleTG.reactor, socket);
}

int swoole_event_wait() {
    Reactor *reactor = SwooleTG.reactor;
    int retval = 0;
    if (!reactor->wait_exit or !reactor->if_exit()) {
        retval = SwooleTG.reactor->wait(SwooleTG.reactor, nullptr);
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

void swoole_event_defer(swCallback cb, void *private_data) {
    SwooleTG.reactor->defer(cb, private_data);
}

/**
 * @return SW_OK or SW_ERR
 */
ssize_t swoole_event_write(Socket *socket, const void *data, size_t len) {
    return SwooleTG.reactor->write(SwooleTG.reactor, socket, data, len);
}

bool swoole_event_set_handler(int fdtype, swReactor_handler handler) {
    return SwooleTG.reactor->set_handler(fdtype, handler);
}

bool swoole_event_isset_handler(int fdtype) {
    return SwooleTG.reactor->isset_handler(fdtype);
}

bool swoole_event_is_available() {
    return SwooleTG.reactor and !SwooleTG.reactor->destroyed;
}
