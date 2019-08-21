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

#ifdef SW_CO_MT
#include <mutex>
#include <thread>
#define sw_reactor()           (SwooleTG.reactor)
std::once_flag init_flag;
#else
#define sw_reactor()           (SwooleG.main_reactor)
#endif

int swoole_event_init()
{
#ifdef SW_CO_MT
    call_once(init_flag, swoole_init);
    SwooleTG.reactor = (swReactor *) sw_malloc(sizeof(swReactor));
#else
    SwooleG.main_reactor = (swReactor *) sw_malloc(sizeof(swReactor));
#endif
    if (!sw_reactor())
    {
        swSysWarn("malloc failed.");
        return SW_ERR;
    }
    if (swReactor_create(sw_reactor(), SW_REACTOR_MAXEVENTS) < 0)
    {
        sw_free(sw_reactor());
        sw_reactor() = NULL;
        return SW_ERR;
    }
    return SW_OK;
}

uchar swoole_event_add(int fd, int events, int fdtype)
{
    return sw_reactor()->add(sw_reactor(), fd, fdtype | events) == SW_OK;
}

uchar swoole_event_set(int fd, int events, int fdtype)
{
    return sw_reactor()->set(sw_reactor(), fd, fdtype | events) == SW_OK;
}

uchar swoole_event_del(int fd)
{
    return sw_reactor()->del(sw_reactor(), fd);
}

int swoole_event_wait()
{
    int retval = sw_reactor()->wait(sw_reactor(), NULL);
    swoole_event_free();
    return retval;
}

int swoole_event_free()
{
    if (!sw_reactor())
    {
        return SW_ERR;
    }
    swReactor_destroy(sw_reactor());
    sw_free(sw_reactor());
    sw_reactor() = NULL;
    return SW_OK;
}

void swoole_event_defer(swCallback cb, void *private_data)
{
    sw_reactor()->defer(sw_reactor(), cb, private_data);
}
