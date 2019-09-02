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

#include <mutex>
#include <thread>

using namespace std;

static mutex init_lock;

int swoole_event_init()
{
    if (!SwooleG.init)
    {
        unique_lock<mutex> lock(init_lock);
        swoole_init();
        return SW_ERR;
    }

    SwooleTG.reactor = (swReactor *) sw_malloc(sizeof(swReactor));
    if (!SwooleTG.reactor)
    {
        swSysWarn("malloc failed");
        return SW_ERR;
    }
    if (swReactor_create(SwooleTG.reactor, SW_REACTOR_MAXEVENTS) < 0)
    {
        sw_free(SwooleTG.reactor);
        SwooleTG.reactor = nullptr;
        return SW_ERR;
    }
    return SW_OK;
}

int swoole_event_add(int fd, int events, int fdtype)
{
    return SwooleTG.reactor->add(SwooleTG.reactor, fd, fdtype | events);
}

int swoole_event_set(int fd, int events, int fdtype)
{
    return SwooleTG.reactor->set(SwooleTG.reactor, fd, fdtype | events);
}

int swoole_event_del(int fd)
{
    return SwooleTG.reactor->del(SwooleTG.reactor, fd);
}

int swoole_event_wait()
{
    swReactor *reactor = SwooleTG.reactor;
    int retval = 0;
    if (!reactor->is_empty(reactor))
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
    swReactor_destroy(SwooleTG.reactor);
    sw_free(SwooleTG.reactor);
    SwooleTG.reactor = nullptr;
    return SW_OK;
}

void swoole_event_defer(swCallback cb, void *private_data)
{
    SwooleTG.reactor->defer(SwooleTG.reactor, cb, private_data);
}

/**
 * @return SW_OK or SW_ERR
 */
int swoole_event_write(int fd, const void *data, size_t len)
{
    return SwooleTG.reactor->write(SwooleTG.reactor, fd, data, len);
}
