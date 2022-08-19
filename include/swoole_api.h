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
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#pragma once

#include "swoole.h"
#include "swoole_coroutine_c_api.h"

enum swEventInitFlag {
    SW_EVENTLOOP_WAIT_EXIT = 1,
};

SW_API long swoole_timer_after(long ms, const swoole::TimerCallback &callback, void *private_data = nullptr);
SW_API long swoole_timer_tick(long ms, const swoole::TimerCallback &callback, void *private_data = nullptr);
SW_API swoole::TimerNode *swoole_timer_add(double ms,
                                           bool persistent,
                                           const swoole::TimerCallback &callback,
                                           void *private_data = nullptr);
SW_API swoole::TimerNode *swoole_timer_add(long ms,
                                           bool persistent,
                                           const swoole::TimerCallback &callback,
                                           void *private_data = nullptr);
SW_API bool swoole_timer_del(swoole::TimerNode *tnode);
SW_API bool swoole_timer_exists(long timer_id);
SW_API void swoole_timer_delay(swoole::TimerNode *tnode, long delay_ms);
SW_API swoole::TimerNode *swoole_timer_get(long timer_id);
SW_API bool swoole_timer_clear(long timer_id);
SW_API void swoole_timer_free();
SW_API int swoole_timer_select();
SW_API bool swoole_timer_is_available();

SW_API int swoole_event_init(int flags);
SW_API int swoole_event_add(swoole::network::Socket *socket, int events);
SW_API int swoole_event_set(swoole::network::Socket *socket, int events);
SW_API int swoole_event_add_or_update(swoole::network::Socket *socket, int event);
SW_API int swoole_event_del(swoole::network::Socket *socket);
SW_API void swoole_event_defer(swoole::Callback cb, void *private_data);
SW_API ssize_t swoole_event_write(swoole::network::Socket *socket, const void *data, size_t len);
SW_API ssize_t swoole_event_writev(swoole::network::Socket *socket, const iovec *iov, size_t iovcnt);
SW_API swoole::network::Socket *swoole_event_get_socket(int fd);
SW_API int swoole_event_wait();
SW_API int swoole_event_free();
SW_API bool swoole_event_set_handler(int fdtype, swoole::ReactorHandler handler);
SW_API bool swoole_event_isset_handler(int fdtype);
SW_API bool swoole_event_is_available();

#ifdef __MACH__
swoole::Reactor *sw_reactor();
swoole::Timer *sw_timer();
#else
#define sw_reactor() (SwooleTG.reactor)
#define sw_timer() (SwooleTG.timer)
#endif
