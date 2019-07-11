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

#include "wrapper/server.hpp"

namespace swoole
{
void event_init(void)
{
//        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_READ, php_swoole_event_onRead);
//        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_WRITE, php_swoole_event_onWrite);
//        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_ERROR, php_swoole_event_onError);
}

void event_wait(void)
{
    if (!SwooleG.main_reactor)
    {
        return;
    }

#ifdef HAVE_SIGNALFD
    if (SwooleG.main_reactor->check_signalfd)
    {
        swSignalfd_setup(SwooleG.main_reactor);
    }
#endif
    int ret = SwooleG.main_reactor->wait(SwooleG.main_reactor, NULL);
    if (ret < 0)
    {
        swSysWarn("reactor wait failed");
    }
}

void check_reactor(void)
{
    swoole_init();
    if (SwooleG.main_reactor)
    {
        return;
    }

    if (swIsTaskWorker())
    {
        swWarn("cannot use async-io in task process");
    }

    if (SwooleG.main_reactor == NULL)
    {
        swTraceLog(SW_TRACE_PHP, "init reactor");

        SwooleG.main_reactor = (swReactor *) malloc(sizeof(swReactor));
        if (SwooleG.main_reactor == NULL)
        {
            swWarn("malloc failed");
        }
        if (swReactor_create(SwooleG.main_reactor, SW_REACTOR_MAXEVENTS) < 0)
        {
            swWarn("create reactor failed");
        }
    }

    event_init();
}
}
