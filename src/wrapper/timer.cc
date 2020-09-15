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
#include "swoole_timer.h"
#include "swoole_log.h"

using namespace swoole;

#ifdef __MACH__
Timer *sw_timer() {
    return SwooleTG.timer;
}
#endif

TimerNode *swoole_timer_add(long ms, bool persistent, const swTimerCallback &callback, void *private_data) {
    if (sw_unlikely(SwooleTG.timer == nullptr)) {
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
    return SwooleTG.timer->remove(tnode);
}

long swoole_timer_after(long ms, const swTimerCallback &callback, void *private_data) {
    if (ms <= 0) {
        swWarn("Timer must be greater than 0");
        return SW_ERR;
    }
    TimerNode *tnode = swoole_timer_add(ms, false, callback, private_data);
    if (tnode == nullptr) {
        return SW_ERR;
    } else {
        return tnode->id;
    }
}

long swoole_timer_tick(long ms, const swTimerCallback &callback, void *private_data) {
    if (ms <= 0) {
        swWarn("Timer must be greater than 0");
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
    if (!SwooleTG.timer) {
        swWarn("no timer");
        return false;
    }
    TimerNode *tnode = SwooleTG.timer->get(timer_id);
    return (tnode && !tnode->removed);
}

bool swoole_timer_clear(long timer_id) {
    return SwooleTG.timer->remove(SwooleTG.timer->get(timer_id));
}

TimerNode *swoole_timer_get(long timer_id) {
    if (!SwooleTG.timer) {
        swWarn("no timer");
        return nullptr;
    }
    return SwooleTG.timer->get(timer_id);
}

void swoole_timer_free() {
    if (!SwooleTG.timer) {
        return;
    }
    delete SwooleTG.timer;
    SwooleTG.timer = nullptr;
    SwooleG.signal_alarm = false;
}

int swoole_timer_select() {
    if (!SwooleTG.timer) {
        return SW_ERR;
    }
    return SwooleTG.timer->select();
}
