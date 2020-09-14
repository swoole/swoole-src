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
 +----------------------------------------------------------------------+
 */

#include "swoole_api.h"
#include "swoole_reactor.h"
#include "swoole_timer.h"
#include "swoole_util.h"
#include "swoole_log.h"

#if !defined(HAVE_CLOCK_GETTIME) && defined(__MACH__)
#include <mach/clock.h>
#include <mach/mach_time.h>
#include <sys/sysctl.h>

#define ORWL_NANO (+1.0E-9)
#define ORWL_GIGA UINT64_C(1000000000)

static double orwl_timebase = 0.0;
static uint64_t orwl_timestart = 0;

static int clock_gettime(clock_id_t which_clock, struct timespec *t) {
    // be more careful in a multithreaded environement
    if (!orwl_timestart) {
        mach_timebase_info_data_t tb = {0};
        mach_timebase_info(&tb);
        orwl_timebase = tb.numer;
        orwl_timebase /= tb.denom;
        orwl_timestart = mach_absolute_time();
    }
    double diff = (mach_absolute_time() - orwl_timestart) * orwl_timebase;
    t->tv_sec = diff * ORWL_NANO;
    t->tv_nsec = diff - (t->tv_sec * ORWL_GIGA);
    return 0;
}
#endif

namespace swoole {

Timer::Timer() {
    heap = swHeap_new(1024, SW_MIN_HEAP);
    if (!heap) {
        throw std::bad_alloc();
    }
    _current_id = -1;
    next_msec_ = -1;
    _next_id = 1;
    round = 0;
}

bool Timer::init() {
    if (now(&base_time) < 0) {
        return false;
    }
    if (SwooleTG.reactor) {
        return init_reactor(SwooleTG.reactor);
    } else {
        return init_system_timer();
    }
}

bool Timer::init_reactor(swReactor *reactor) {
    reactor_ = reactor;
    set = [](Timer *timer, long exec_msec) -> int {
        timer->reactor_->timeout_msec = exec_msec;
        return SW_OK;
    };
    close = [](swTimer *timer) { timer->set(timer, -1); };

    reactor->set_end_callback(Reactor::PRIORITY_TIMER, [this](swReactor *) { select(); });

    reactor->set_exit_condition(Reactor::EXIT_CONDITION_TIMER,
                                [this](swReactor *reactor, int &event_num) -> bool { return count() == 0; });

    reactor->add_destroy_callback([](void *) { swoole_timer_free(); });

    return true;
}

void Timer::reinit(swReactor *reactor) {
    init_reactor(reactor);
    reactor->timeout_msec = next_msec_;
}

Timer::~Timer() {
    if (close) {
        close(this);
    }
    if (heap) {
        swHeap_free(heap);
    }
    for (auto iter = map.begin(); iter != map.end(); iter++) {
        auto tnode = iter->second;
        delete tnode;
    }
}

TimerNode *Timer::add(long _msec, bool persistent, void *data, const swTimerCallback &callback) {
    if (sw_unlikely(_msec <= 0)) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_INVALID_PARAMS, "msec value[%ld] is invalid", _msec);
        return nullptr;
    }

    int64_t now_msec = get_relative_msec();
    if (sw_unlikely(now_msec < 0)) {
        return nullptr;
    }

    TimerNode *tnode = new TimerNode();
    tnode->data = data;
    tnode->type = TimerNode::TYPE_KERNEL;
    tnode->exec_msec = now_msec + _msec;
    tnode->interval = persistent ? _msec : 0;
    tnode->removed = false;
    tnode->callback = callback;
    tnode->round = round;
    tnode->destructor = nullptr;

    if (next_msec_ < 0 || next_msec_ > _msec) {
        set(this, _msec);
        next_msec_ = _msec;
    }

    tnode->id = _next_id++;
    if (sw_unlikely(tnode->id < 0)) {
        tnode->id = 1;
        _next_id = 2;
    }

    tnode->heap_node = swHeap_push(heap, tnode->exec_msec, tnode);
    if (sw_unlikely(tnode->heap_node == nullptr)) {
        delete tnode;
        return nullptr;
    }
    map.emplace(std::make_pair(tnode->id, tnode));
    swTraceLog(SW_TRACE_TIMER,
               "id=%ld, exec_msec=%" PRId64 ", msec=%ld, round=%" PRIu64 ", exist=%u",
               tnode->id,
               tnode->exec_msec,
               _msec,
               tnode->round,
               count());
    return tnode;
}

bool Timer::remove(TimerNode *tnode) {
    if (sw_unlikely(!tnode || tnode->removed)) {
        return false;
    }
    if (sw_unlikely(_current_id > 0 && tnode->id == _current_id)) {
        tnode->removed = true;
        swTraceLog(SW_TRACE_TIMER,
                   "set-remove: id=%ld, exec_msec=%" PRId64 ", round=%" PRIu64 ", exist=%u",
                   tnode->id,
                   tnode->exec_msec,
                   tnode->round,
                   count());
        return true;
    }
    if (sw_unlikely(!map.erase(tnode->id))) {
        return false;
    }
    if (tnode->heap_node) {
        swHeap_remove(heap, tnode->heap_node);
        sw_free(tnode->heap_node);
    }
    if (tnode->destructor) {
        tnode->destructor(tnode);
    }
    swTraceLog(SW_TRACE_TIMER,
               "id=%ld, exec_msec=%" PRId64 ", round=%" PRIu64 ", exist=%u",
               tnode->id,
               tnode->exec_msec,
               tnode->round,
               count());
    delete tnode;
    return true;
}

int Timer::select() {
    int64_t now_msec = get_relative_msec();
    if (sw_unlikely(now_msec < 0)) {
        return SW_ERR;
    }

    TimerNode *tnode = nullptr;
    swHeap_node *tmp;

    swTraceLog(SW_TRACE_TIMER, "timer msec=%" PRId64 ", round=%" PRId64, now_msec, round);

    while ((tmp = swHeap_top(heap))) {
        tnode = (TimerNode *) tmp->data;
        if (tnode->exec_msec > now_msec || tnode->round == round) {
            break;
        }

        _current_id = tnode->id;
        if (!tnode->removed) {
            swTraceLog(SW_TRACE_TIMER,
                       "id=%ld, exec_msec=%" PRId64 ", round=%" PRIu64 ", exist=%u",
                       tnode->id,
                       tnode->exec_msec,
                       tnode->round,
                       count() - 1);
            tnode->callback(this, tnode);
        }
        _current_id = -1;

        // persistent timer
        if (tnode->interval > 0 && !tnode->removed) {
            while (tnode->exec_msec <= now_msec) {
                tnode->exec_msec += tnode->interval;
            }
            swHeap_change_priority(heap, tnode->exec_msec, tmp);
            continue;
        }

        swHeap_pop(heap);
        map.erase(tnode->id);
        delete tnode;
    }

    if (!tnode || !tmp) {
        next_msec_ = -1;
        set(this, -1);
    } else {
        long next_msec = tnode->exec_msec - now_msec;
        if (next_msec <= 0) {
            next_msec = 1;
        }
        set(this, next_msec);
    }
    round++;

    return SW_OK;
}

#if defined(SW_USE_MONOTONIC_TIME) && defined(CLOCK_MONOTONIC)
int Timer::now(struct timeval *time) {
    struct timespec _now;
    if (clock_gettime(CLOCK_MONOTONIC, &_now) < 0) {
        swSysWarn("clock_gettime(CLOCK_MONOTONIC) failed");
        return SW_ERR;
    }
    time->tv_sec = _now.tv_sec;
    time->tv_usec = _now.tv_nsec / 1000;
#else
if (gettimeofday(time, nullptr) < 0) {
    swSysWarn("gettimeofday() failed");
    return SW_ERR;
}
#endif
    return SW_OK;
}  // namespace swoole

};  // namespace swoole
