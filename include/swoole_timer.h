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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"
#include "heap.h"
#include "swoole_reactor.h"

#include <unordered_map>

#define SW_TIMER_MIN_MS 1
#define SW_TIMER_MIN_SEC 0.001
#define SW_TIMER_MAX_MS LONG_MAX
#define SW_TIMER_MAX_SEC ((double) (LONG_MAX / 1000))

enum swTimer_type {
    SW_TIMER_TYPE_KERNEL,
    SW_TIMER_TYPE_PHP,
};

struct swTimer_node {
    long id;
    enum swTimer_type type;
    int64_t exec_msec;
    int64_t interval;
    uint64_t round;
    bool removed;
    swHeap_node *heap_node;
    swTimerCallback callback;
    void *data;
    swTimerDestructor destructor;
};

struct swTimer {
    /*--------------signal timer--------------*/
    swReactor *reactor;
    swHeap *heap;
    std::unordered_map<long, swTimer_node *> *map;
    uint32_t num;
    uint64_t round;
    long _next_id;
    long _current_id;
    long _next_msec;
    /*---------------event timer--------------*/
    struct timeval base_time;
    /*---------------system timer-------------*/
    long last_time;
    /*----------------------------------------*/
    int (*set)(swTimer *timer, long exec_msec);
    void (*close)(swTimer *timer);
};

int swTimer_init(swTimer *timer, long msec);
void swTimer_reinit(swTimer *timer, swReactor *reactor);
bool swTimer_del(swTimer *timer, swTimer_node *node);
void swTimer_free(swTimer *timer);
int swTimer_select(swTimer *timer);
int swTimer_now(struct timeval *time);

static sw_inline swTimer_node *swTimer_get(swTimer *timer, long id) {
    auto it = timer->map->find(id);
    if (it == timer->map->end()) {
        return nullptr;
    } else {
        return it->second;
    }
}

static sw_inline swTimer_node *swTimer_get_ex(swTimer *timer, long id, const enum swTimer_type type) {
    swTimer_node *tnode = swTimer_get(timer, id);
    return (tnode && tnode->type == type) ? tnode : NULL;
}

static sw_inline int64_t swTimer_get_relative_msec() {
    struct timeval now;
    if (!SwooleTG.timer) {
        return SW_ERR;
    }
    if (swTimer_now(&now) < 0) {
        return SW_ERR;
    }
    int64_t msec1 = (now.tv_sec - SwooleTG.timer->base_time.tv_sec) * 1000;
    int64_t msec2 = (now.tv_usec - SwooleTG.timer->base_time.tv_usec) / 1000;
    return msec1 + msec2;
}

static sw_inline int64_t swTimer_get_absolute_msec() {
    struct timeval now;
    if (swTimer_now(&now) < 0) {
        return SW_ERR;
    }
    int64_t msec1 = (now.tv_sec) * 1000;
    int64_t msec2 = (now.tv_usec) / 1000;
    return msec1 + msec2;
}
