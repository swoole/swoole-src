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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"

static void swReactor_onTimeout_and_Finish(swReactor *reactor);
static void swReactor_onTimeout(swReactor *reactor);
static void swReactor_onFinish(swReactor *reactor);

int swReactor_auto(swReactor *reactor, int max_event)
{
    int ret;

    //event less than SW_REACTOR_MINEVENTS, use poll/select
    if (max_event <= SW_REACTOR_MINEVENTS)
    {
#ifdef SW_MAINREACTOR_USE_POLL
        ret = swReactorPoll_create(reactor, SW_REACTOR_MINEVENTS);
#else
        ret = swReactorSelect_create(reactor);
#endif
    }
    //use epoll or kqueue
    else
    {
#ifdef HAVE_EPOLL
        ret = swReactorEpoll_create(reactor, max_event);
#elif defined(HAVE_KQUEUE)
        ret = swReactorKqueue_create(reactor, max_event);
#elif defined(SW_MAINREACTOR_USE_POLL)
        ret = swReactorPoll_create(reactor, max_event);
#else
        ret = swReactorSelect_create(SwooleG.main_reactor);
#endif
    }

    reactor->onFinish = swReactor_onFinish;
    reactor->onTimeout = swReactor_onTimeout;

    return ret;
}

swReactor_handle swReactor_getHandle(swReactor *reactor, int event_type, int fdtype)
{
    if (event_type == SW_EVENT_WRITE)
    {
        return (reactor->write_handle[fdtype] != NULL) ? reactor->write_handle[fdtype] : reactor->handle[SW_FD_WRITE];
    }
    if (event_type == SW_EVENT_ERROR)
    {
        return (reactor->error_handle[fdtype] != NULL) ? reactor->error_handle[fdtype] : reactor->handle[SW_FD_CLOSE];
    }
    return reactor->handle[fdtype];
}

int swReactor_setHandle(swReactor *reactor, int _fdtype, swReactor_handle handle)
{
    int fdtype = swReactor_fdtype(_fdtype);

    if (fdtype >= SW_MAX_FDTYPE)
    {
        swWarn("fdtype > SW_MAX_FDTYPE[%d]", SW_MAX_FDTYPE);
        return SW_ERR;
    }
    else
    {
        if (swReactor_event_read(_fdtype))
        {
            reactor->handle[fdtype] = handle;
        }
        else if (swReactor_event_write(_fdtype))
        {
            reactor->write_handle[fdtype] = handle;
        }
        else if (swReactor_event_error(_fdtype))
        {
            reactor->error_handle[fdtype] = handle;
        }
        else
        {
            swWarn("unknow fdtype");
            return SW_ERR;
        }
    }
    return SW_OK;
}

/**
 * execute when reactor timeout and reactor finish
 */
static void swReactor_onTimeout_and_Finish(swReactor *reactor)
{
    //check timer
    if (reactor->check_timer)
    {
        SwooleG.timer.select(&SwooleG.timer);
    }
    if (SwooleG.serv && swIsMaster())
    {
        swoole_update_time();
    }
}

static void swReactor_onTimeout(swReactor *reactor)
{
    swReactor_onTimeout_and_Finish(reactor);
}

static void swReactor_onFinish(swReactor *reactor)
{
    //client exit
    if (SwooleG.serv == NULL && reactor->event_num == 0)
    {
        SwooleG.running = 0;
    }
    //check signal
    if (reactor->singal_no)
    {
        swSignal_callback(reactor->singal_no);
        reactor->singal_no = 0;
    }
    swReactor_onTimeout_and_Finish(reactor);
}
