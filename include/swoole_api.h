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

#include "swoole.h"
#include "coroutine_c_api.h"

SW_EXTERN_C_BEGIN

SW_API long swoole_timer_after(long ms, swTimerCallback callback, void *private_data);
SW_API long swoole_timer_tick(long ms, swTimerCallback callback, void *private_data);
SW_API swTimer_node* swoole_timer_add(long ms, uchar persistent, swTimerCallback callback, void *private_data);
SW_API uchar swoole_timer_del(swTimer_node* tnode);
SW_API uchar swoole_timer_exists(long timer_id);
SW_API swTimer_node* swoole_timer_get(long timer_id);
SW_API uchar swoole_timer_clear(long timer_id);
SW_API void swoole_timer_free();

SW_API int swoole_event_init();
SW_API int swoole_event_add(swSocket *socket, int events);
SW_API int swoole_event_set(swSocket *socket, int events);
SW_API int swoole_event_del(swSocket *socket);
SW_API void swoole_event_defer(swCallback cb, void *private_data);
SW_API int swoole_event_write(swSocket *socket, const void *data, size_t len);
SW_API int swoole_event_wait();
SW_API int swoole_event_free();

#ifdef __MACH__
swReactor* sw_reactor();
swTimer* sw_timer();
#else
#define sw_reactor()       (SwooleTG.reactor)
#define sw_timer()         (SwooleTG.timer)
#endif

SW_EXTERN_C_END

#endif /* _SW_API_H_ */
