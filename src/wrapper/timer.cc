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

using namespace swoole;

#ifdef __MACH__
Timer *sw_timer() {
    return SwooleTG.timer;
}
#endif

bool swoole_timer_is_available() {
    return SwooleTG.timer != nullptr;
}

TimerNode *swoole_timer_add(double timeout, bool persistent, const TimerCallback &callback, void *private_data) {
    if (timeout < SW_TIMER_MIN_SEC) {
        return swoole_timer_add(1L, persistent, callback, private_data);
    }

    return swoole_timer_add((long) (timeout * 1000), persistent, callback, private_data);
}

TimerNode *swoole_timer_add(long ms, bool persistent, const TimerCallback &callback, void *private_data) {
    if (sw_unlikely(!swoole_timer_is_available())) {
        SwooleTG.timer = new Timer();
        if (sw_unlikely(!SwooleTG.timer->init())) {
            delete SwooleTG.timer;
            SwooleTG.timer = nullptr;
            return nullptr;
        }
    }
    return SwooleTG.timer->add(ms, persistent, private_data, callback);
}

bool swoole_timer_del(TimerNode *tnode) {
    if (!swoole_timer_is_available()) {
        swoole_warning("timer is not available");
        return false;
    }
    return SwooleTG.timer->remove(tnode);
}

void swoole_timer_delay(TimerNode *tnode, long delay_ms) {
    if (!swoole_timer_is_available()) {
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
    TimerNode *tnode = swoole_timer_add(ms, false, callback, private_data);
    if (tnode == nullptr) {
        return SW_ERR;
    } else {
        return tnode->id;
    }
}

long swoole_timer_tick(long ms, const TimerCallback &callback, void *private_data) {
    if (ms <= 0) {
        swoole_warning("Timer must be greater than 0");
        return SW_ERR;
    }
    TimerNode *tnode = swoole_timer_add(ms, true, callback, private_data);
    if (tnode == nullptr) {
        return SW_ERR;
    } else {
        return tnode->id;
    }
}

bool swoole_timer_exists(long timer_id) {
    if (!swoole_timer_is_available()) {
        swoole_warning("timer is not available");
        return false;
    }
    TimerNode *tnode = SwooleTG.timer->get(timer_id);
    return (tnode && !tnode->removed);
}

bool swoole_timer_clear(long timer_id) {
    if (!swoole_timer_is_available()) {
        swoole_warning("timer is not available");
        return false;
    }
    return SwooleTG.timer->remove(SwooleTG.timer->get(timer_id));
}

TimerNode *swoole_timer_get(long timer_id) {
    if (!swoole_timer_is_available()) {
        swoole_warning("timer is not available");
        return nullptr;
    }
    return SwooleTG.timer->get(timer_id);
}

void swoole_timer_free() {
    if (!swoole_timer_is_available()) {
        swoole_warning("timer is not available");
        return;
    }
    delete SwooleTG.timer;
    SwooleTG.timer = nullptr;
    SwooleG.signal_alarm = false;
}

int swoole_timer_select() {
    if (!swoole_timer_is_available()) {
        swoole_warning("timer is not available");
        return SW_ERR;
    }
    return SwooleTG.timer->select();
}
