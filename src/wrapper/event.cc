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
#include "client.h"
#include "async.h"
#include "coroutine_c_api.h"
#include "coroutine_socket.h"
#include "coroutine_system.h"

#include <mutex>
#include <thread>

using namespace std;
using swoole::coroutine::Socket;
using swoole::coroutine::System;

static mutex init_lock;

#ifdef __MACH__
swReactor* sw_reactor()
{
    return SwooleTG.reactor;
}
#endif

int swoole_event_init(int flags)
{
    if (!SwooleG.init)
    {
        unique_lock<mutex> lock(init_lock);
        swoole_init();
    }

    swReactor *reactor = new swoole::Reactor(SW_REACTOR_MAXEVENTS);
    if (flags & SW_EVENTLOOP_WAIT_EXIT)
    {
        reactor->wait_exit = 1;
    }

    Socket::init_reactor(reactor);
    System::init_reactor(reactor);
    swClient_init_reactor(reactor);

    SwooleTG.reactor = reactor;

    return SW_OK;
}

int swoole_event_add(swSocket *socket, int events)
{
    return SwooleTG.reactor->add(SwooleTG.reactor, socket, events);
}

int swoole_event_set(swSocket *socket, int events)
{
    return SwooleTG.reactor->set(SwooleTG.reactor, socket, events);
}

int swoole_event_del(swSocket *socket)
{
    return SwooleTG.reactor->del(SwooleTG.reactor, socket);
}

int swoole_event_wait()
{
    swReactor *reactor = SwooleTG.reactor;
    int retval = 0;
    if (!reactor->wait_exit or !reactor->if_exit())
    {
        retval = SwooleTG.reactor->wait(SwooleTG.reactor, nullptr);
    }
    swoole_event_free();
    return retval;
}

int swoole_event_free()
{
    if (!SwooleTG.reactor)
    {
        return SW_ERR;
    }
    delete SwooleTG.reactor;
    SwooleTG.reactor = nullptr;
    return SW_OK;
}

void swoole_event_defer(swCallback cb, void *private_data)
{
    SwooleTG.reactor->defer(cb, private_data);
}

/**
 * @return SW_OK or SW_ERR
 */
int swoole_event_write(swSocket *socket, const void *data, size_t len)
{
    return SwooleTG.reactor->write(SwooleTG.reactor, socket, data, len);
}

int swoole_event_set_handler(int fdtype, swReactor_handler handler)
{
    return SwooleTG.reactor->set_handler(fdtype, handler);
}

int swoole_event_isset_handler(int fdtype)
{
    return SwooleTG.reactor->isset_handler(fdtype);
}
