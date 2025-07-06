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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "swoole_api.h"
#include "swoole_timer.h"

using swoole::sec2msec;
using swoole::Timer;
using swoole::TimerCallback;
using swoole::TimerNode;

bool swoole_timer_is_available() {
    return SwooleTG.timer != nullptr;
}

TimerNode *swoole_timer_add(double timeout, bool persistent, const TimerCallback &callback, void *private_data) {
    if (sw_unlikely(timeout < SW_TIMER_MIN_SEC)) {
        timeout = SW_TIMER_MIN_SEC;
    }
    return swoole_timer_add(sec2msec(timeout), persistent, callback, private_data);
}

Timer *swoole_timer_create(bool manually_trigger) {
    SwooleTG.timer = new Timer(manually_trigger);
    return SwooleTG.timer;
}

SW_API int64_t swoole_timer_get_next_msec() {
    if (sw_unlikely(!swoole_timer_is_available())) {
        return -1;
    }
    return SwooleTG.timer->get_next_msec();
}

TimerNode *swoole_timer_add(long ms, bool persistent, const TimerCallback &callback, void *private_data) {
    if (sw_unlikely(!swoole_timer_is_available())) {
        swoole_timer_create(false);
    }
    return SwooleTG.timer->add(ms, persistent, private_data, callback);
}

bool swoole_timer_del(TimerNode *tnode) {
    if (sw_unlikely(!swoole_timer_is_available())) {
        swoole_warning("timer is not available");
        return false;
    }
    return SwooleTG.timer->remove(tnode);
}

void swoole_timer_delay(TimerNode *tnode, long delay_ms) {
    if (sw_unlikely(!swoole_timer_is_available())) {
        swoole_warning("timer is not available");
        return;
    }
    return SwooleTG.timer->delay(tnode, delay_ms);
}

long swoole_timer_after(long ms, const TimerCallback &callback, void *private_data) {
    if (ms <= 0) {
        swoole_warning("Timer must be greater than 0");
        return SW_ERR;
    }
    const auto tnode = swoole_timer_add(ms, false, callback, private_data);
    if (sw_unlikely(!tnode)) {
        return SW_ERR;
    }
    return tnode->id;
}

long swoole_timer_tick(long ms, const TimerCallback &callback, void *private_data) {
    if (sw_unlikely(ms <= 0)) {
        swoole_warning("Timer must be greater than 0");
        return SW_ERR;
    }
    const auto tnode = swoole_timer_add(ms, true, callback, private_data);
    if (sw_unlikely(!tnode)) {
        return SW_ERR;
    }
    return tnode->id;
}

bool swoole_timer_exists(long timer_id) {
    if (sw_unlikely(!swoole_timer_is_available())) {
        swoole_warning("timer is not available");
        return false;
    }
    TimerNode *tnode = SwooleTG.timer->get(timer_id);
    return (tnode && !tnode->removed);
}

bool swoole_timer_clear(long timer_id) {
    if (sw_unlikely(!swoole_timer_is_available())) {
        swoole_warning("timer is not available");
        return false;
    }
    return SwooleTG.timer->remove(SwooleTG.timer->get(timer_id));
}

TimerNode *swoole_timer_get(long timer_id) {
    if (sw_unlikely(!swoole_timer_is_available())) {
        swoole_warning("timer is not available");
        return nullptr;
    }
    return SwooleTG.timer->get(timer_id);
}

void swoole_timer_free() {
    if (!swoole_timer_is_available()) {
        swoole_print_backtrace();
        swoole_warning("timer is not available");
        return;
    }
    delete SwooleTG.timer;
    SwooleTG.timer = nullptr;
}

void swoole_timer_select() {
    if (sw_likely(swoole_timer_is_available())) {
        SwooleTG.timer->select();
    }
}
