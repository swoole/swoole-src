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

int swoole_event_init()
{
    swoole_init();
    SwooleG.main_reactor = (swReactor *) sw_malloc(sizeof(swReactor));
    if (!SwooleG.main_reactor)
    {
        return SW_ERR;
    }
    return swReactor_create(SwooleG.main_reactor, SW_REACTOR_MAXEVENTS);
}

uchar swoole_event_add(int fd, int events, int fdtype)
{
    return SwooleG.main_reactor->add(SwooleG.main_reactor, fd, fdtype | events) == SW_OK;
}

uchar swoole_event_set(int fd, int events, int fdtype)
{
    return SwooleG.main_reactor->set(SwooleG.main_reactor, fd, fdtype | events) == SW_OK;
}

uchar swoole_event_del(int fd)
{
    return SwooleG.main_reactor->del(SwooleG.main_reactor, fd);
}

int swoole_event_wait()
{
    return SwooleG.main_reactor->wait(SwooleG.main_reactor, NULL);
}

void swoole_event_defer(swCallback cb, void *private_data)
{
    SwooleG.main_reactor->defer(SwooleG.main_reactor, cb, private_data);
}

