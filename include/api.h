/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2018 The Swoole Group                             |
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

#ifndef _SW_API_H_
#define _SW_API_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "swoole.h"
#include "coroutine_c_api.h"

long swoole_timer_after(long ms, swTimerCallback callback, void *private_data);
long swoole_timer_tick(long ms, swTimerCallback callback, void *private_data);
long swoole_timer_add(long ms, uchar persistent, swTimerCallback callback, void *private_data);
uchar swoole_timer_exists(long timer_id);
uchar swoole_timer_clear(long timer_id);

static inline int swoole_event_init()
{
    swoole_init();
    SwooleG.main_reactor = (swReactor *) sw_malloc(sizeof(swReactor));
    return swReactor_create(SwooleG.main_reactor, SW_REACTOR_MAXEVENTS);
}

static inline uchar swoole_event_add(int fd, int events, int fdtype)
{
    return SwooleG.main_reactor->add(SwooleG.main_reactor, fd, fdtype | events) == SW_OK;
}

static inline uchar swoole_event_set(int fd, int events, int fdtype)
{
    return SwooleG.main_reactor->set(SwooleG.main_reactor, fd, fdtype | events) == SW_OK;
}

static inline uchar swoole_event_del(int fd)
{
    return SwooleG.main_reactor->del(SwooleG.main_reactor, fd);
}

static inline int swoole_event_wait()
{
    return SwooleG.main_reactor->wait(SwooleG.main_reactor, NULL);
}

#ifdef __cplusplus
}
#endif

#endif /* _SW_API_H_ */
