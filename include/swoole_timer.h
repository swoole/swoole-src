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
    enum Type type;
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
  private:
    /*--------------signal timer--------------*/
    Reactor *reactor_ = nullptr;
    Heap heap;
    std::unordered_map<long, TimerNode *> map;
    uint64_t round;
    long _next_id;
    long _current_id;
    /*---------------event timer--------------*/
    struct timeval base_time;
    /*----------------------------------------*/
    int (*set)(Timer *timer, long exec_msec) = nullptr;
    void (*close)(Timer *timer) = nullptr;

    bool init_reactor(Reactor *reactor);
    bool init_system_timer();

  public:
    long next_msec_;

    Timer();
    ~Timer();
    static int now(struct timeval *time);

    inline int64_t get_relative_msec() {
        struct timeval _now;
        if (now(&_now) < 0) {
            return SW_ERR;
        }
        int64_t msec1 = (_now.tv_sec - base_time.tv_sec) * 1000;
        int64_t msec2 = (_now.tv_usec - base_time.tv_usec) / 1000;
        return msec1 + msec2;
    }

    inline static int64_t get_absolute_msec() {
        struct timeval now;
        if (Timer::now(&now) < 0) {
            return SW_ERR;
        }
        int64_t msec1 = (now.tv_sec) * 1000;
        int64_t msec2 = (now.tv_usec) / 1000;
        return msec1 + msec2;
    }

    inline Reactor *get_reactor() {
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
    int select();

    inline TimerNode *get(long id) {
        auto it = map.find(id);
        if (it == map.end()) {
            return nullptr;
        } else {
            return it->second;
        }
    }

    inline TimerNode *get(long id, const enum TimerNode::Type type) {
        TimerNode *tnode = get(id);
        return (tnode && tnode->type == type) ? tnode : nullptr;
    }

    inline size_t count() {
        return map.size();
    }

    inline uint64_t get_round() {
        return round;
    }

    inline bool remove(long id) {
        return remove(get(id));
    }

    inline const std::unordered_map<long, TimerNode *> &get_map() {
        return map;
    }
};
}  // namespace swoole
