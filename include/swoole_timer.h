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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"
#include "swoole_heap.h"
#include "swoole_reactor.h"

#include <unordered_map>

#define SW_TIMER_MIN_MS 1
#define SW_TIMER_MIN_SEC 0.001
#define SW_TIMER_MAX_MS LONG_MAX
#define SW_TIMER_MAX_SEC ((double) LONG_MAX / 1000)

namespace swoole {

typedef std::function<void(TimerNode *)> TimerDestructor;

struct TimerNode {
    enum Type {
        TYPE_KERNEL,
        TYPE_PHP,
    };
    long id;
    Type type;
    int64_t exec_msec;
    int64_t interval;
    uint64_t exec_count;
    uint64_t round;
    bool removed;
    HeapNode *heap_node;
    TimerCallback callback;
    void *data;
    TimerDestructor destructor;
};

class Timer {
    /*--------------signal timer--------------*/
    Reactor *reactor_ = nullptr;
    Heap heap;
    std::unordered_map<long, TimerNode *> map;
    uint64_t round;
    long _next_id;
    long _current_id;
    /*---------------event timer--------------*/
    timeval base_time;
    /*----------------------------------------*/
    std::function<int(Timer *timer, long exec_msec)> set;
    std::function<void(Timer *timer)> close;

    bool init_with_reactor(Reactor *reactor);
    bool init_with_user_scheduler(const TimerScheduler &scheduler);
    bool init_with_system_timer();
    void release_node(TimerNode *tnode);

  public:
    long next_msec_;

    Timer();
    ~Timer();
    static int now(timeval *time);

    int64_t get_relative_msec() const {
        timeval _now;
        if (now(&_now) < 0) {
            return SW_ERR;
        }
        int64_t msec1 = (_now.tv_sec - base_time.tv_sec) * 1000;
        int64_t msec2 = (_now.tv_usec - base_time.tv_usec) / 1000;
        return msec1 + msec2;
    }

    static int64_t get_absolute_msec() {
        timeval now;
        if (Timer::now(&now) < 0) {
            return SW_ERR;
        }
        int64_t msec1 = (now.tv_sec) * 1000;
        int64_t msec2 = (now.tv_usec) / 1000;
        return msec1 + msec2;
    }

    Reactor *get_reactor() const {
        return reactor_;
    }

    bool init();
    TimerNode *add(long _msec, bool persistent, void *data, const TimerCallback &callback);
    bool remove(TimerNode *tnode);
    void update(TimerNode *tnode) {
        heap.change_priority(tnode->exec_msec, tnode->heap_node);
    }
    void delay(TimerNode *tnode, long delay_ms) {
        long now_ms = get_relative_msec();
        tnode->exec_msec = (now_ms < 0 ? tnode->exec_msec : now_ms) + delay_ms;
        update(tnode);
    }
    void reinit(Reactor *reactor);
    void reinit(const TimerScheduler &scheduler);
    int select();

    TimerNode *get(long id) {
        auto it = map.find(id);
        if (it == map.end()) {
            return nullptr;
        }
        return it->second;
    }

    TimerNode *get(long id, const TimerNode::Type type) {
        TimerNode *tnode = get(id);
        return (tnode && tnode->type == type) ? tnode : nullptr;
    }

    size_t count() const {
        return map.size();
    }

    uint64_t get_round() const {
        return round;
    }

    bool remove(long id) {
        return remove(get(id));
    }

    const std::unordered_map<long, TimerNode *> &get_map() {
        return map;
    }
};

static inline long sec2msec(const long sec) {
    return sec * 1000;
}

static inline long sec2msec(const int sec) {
    return sec * 1000;
}

static inline long sec2msec(const double sec) {
    return static_cast<long>(sec * 1000);
}
}  // namespace swoole
