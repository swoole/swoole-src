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

int swSystemTimer_init(swTimer *timer, long msec);

int swTimer_now(struct timeval *time) {
#if defined(SW_USE_MONOTONIC_TIME) && defined(CLOCK_MONOTONIC)
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
}

static int swReactorTimer_set(swTimer *timer, long exec_msec) {
    timer->reactor->timeout_msec = exec_msec;
    return SW_OK;
}

static void swReactorTimer_close(swTimer *timer) {
    swReactorTimer_set(timer, -1);
}

static int swReactorTimer_init(swReactor *reactor, swTimer *timer, long exec_msec) {
    reactor->timeout_msec = exec_msec;
    timer->reactor = reactor;
    timer->set = swReactorTimer_set;
    timer->close = swReactorTimer_close;

    reactor->set_end_callback(SW_REACTOR_PRIORITY_TIMER, [timer](swReactor *) { swTimer_select(timer); });

    reactor->set_exit_condition(SW_REACTOR_EXIT_CONDITION_TIMER,
                                [timer](swReactor *reactor, int &event_num) -> bool { return timer->num == 0; });

    reactor->add_destroy_callback([](void *) { swoole_timer_free(); });

    return SW_OK;
}

int swTimer_init(swTimer *timer, long msec) {
    sw_memset_zero(timer, sizeof(swTimer));
    if (swTimer_now(&timer->basetime) < 0) {
        return SW_ERR;
    }

    timer->heap = swHeap_new(1024, SW_MIN_HEAP);
    if (!timer->heap) {
        return SW_ERR;
    }

    timer->map = new std::unordered_map<long, swTimer_node *>;
    timer->_current_id = -1;
    timer->_next_msec = msec;
    timer->_next_id = 1;

    int ret;
    if (SwooleTG.reactor) {
        ret = swReactorTimer_init(SwooleTG.reactor, timer, msec);
    } else {
        ret = swSystemTimer_init(timer, msec);
    }
    if (sw_likely(ret != SW_OK)) {
        swTimer_free(timer);
    }
    return ret;
}

void swTimer_reinit(swTimer *timer, swReactor *reactor) {
    swReactorTimer_init(reactor, timer, timer->_next_msec);
}

void swTimer_free(swTimer *timer) {
    if (timer->close) {
        timer->close(timer);
    }
    if (timer->heap) {
        swHeap_free(timer->heap);
    }
    if (timer->map) {
        for (auto iter = timer->map->begin(); iter != timer->map->end(); iter++) {
            sw_free(iter->second);
        }
        delete timer->map;
    }
    memset(timer, 0, sizeof(swTimer));
}

swTimer_node *swTimer_add(swTimer *timer, long _msec, int interval, void *data, swTimerCallback callback) {
    if (sw_unlikely(_msec <= 0)) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_INVALID_PARAMS, "msec value[%ld] is invalid", _msec);
        return nullptr;
    }

    swTimer_node *tnode = (swTimer_node *) sw_malloc(sizeof(swTimer_node));
    if (sw_unlikely(!tnode)) {
        swSysWarn("malloc(%ld) failed", sizeof(swTimer_node));
        return nullptr;
    }

    int64_t now_msec = swTimer_get_relative_msec();
    if (sw_unlikely(now_msec < 0)) {
        sw_free(tnode);
        return nullptr;
    }

    tnode->data = data;
    tnode->type = SW_TIMER_TYPE_KERNEL;
    tnode->exec_msec = now_msec + _msec;
    tnode->interval = interval ? _msec : 0;
    tnode->removed = 0;
    tnode->callback = callback;
    tnode->round = timer->round;
    tnode->dtor = nullptr;

    if (timer->_next_msec < 0 || timer->_next_msec > _msec) {
        timer->set(timer, _msec);
        timer->_next_msec = _msec;
    }

    tnode->id = timer->_next_id++;
    if (sw_unlikely(tnode->id < 0)) {
        tnode->id = 1;
        timer->_next_id = 2;
    }

    tnode->heap_node = swHeap_push(timer->heap, tnode->exec_msec, tnode);
    if (sw_unlikely(tnode->heap_node == nullptr)) {
        sw_free(tnode);
        return nullptr;
    }
    timer->map->emplace(std::make_pair(tnode->id, tnode));
    timer->num++;
    swTraceLog(SW_TRACE_TIMER,
               "id=%ld, exec_msec=%" PRId64 ", msec=%ld, round=%" PRIu64 ", exist=%u",
               tnode->id,
               tnode->exec_msec,
               _msec,
               tnode->round,
               timer->num);
    return tnode;
}

bool swTimer_del(swTimer *timer, swTimer_node *tnode) {
    if (sw_unlikely(!tnode || tnode->removed)) {
        return false;
    }
    if (sw_unlikely(timer->_current_id > 0 && tnode->id == timer->_current_id)) {
        tnode->removed = 1;
        swTraceLog(SW_TRACE_TIMER,
                   "set-remove: id=%ld, exec_msec=%" PRId64 ", round=%" PRIu64 ", exist=%u",
                   tnode->id,
                   tnode->exec_msec,
                   tnode->round,
                   timer->num);
        return true;
    }
    if (sw_unlikely(!timer->map->erase(tnode->id))) {
        return false;
    }
    if (tnode->heap_node) {
        swHeap_remove(timer->heap, tnode->heap_node);
        sw_free(tnode->heap_node);
    }
    if (tnode->dtor) {
        tnode->dtor(tnode);
    }
    timer->num--;
    swTraceLog(SW_TRACE_TIMER,
               "id=%ld, exec_msec=%" PRId64 ", round=%" PRIu64 ", exist=%u",
               tnode->id,
               tnode->exec_msec,
               tnode->round,
               timer->num);
    sw_free(tnode);
    return true;
}

int swTimer_select(swTimer *timer) {
    int64_t now_msec = swTimer_get_relative_msec();
    if (sw_unlikely(now_msec < 0)) {
        return SW_ERR;
    }

    swTimer_node *tnode = nullptr;
    swHeap_node *tmp;

    swTraceLog(SW_TRACE_TIMER, "timer msec=%" PRId64 ", round=%" PRId64, now_msec, timer->round);
    while ((tmp = swHeap_top(timer->heap))) {
        tnode = (swTimer_node *) tmp->data;
        if (tnode->exec_msec > now_msec || tnode->round == timer->round) {
            break;
        }

        timer->_current_id = tnode->id;
        if (!tnode->removed) {
            swTraceLog(SW_TRACE_TIMER,
                       "id=%ld, exec_msec=%" PRId64 ", round=%" PRIu64 ", exist=%u",
                       tnode->id,
                       tnode->exec_msec,
                       tnode->round,
                       timer->num - 1);
            tnode->callback(timer, tnode);
        }
        timer->_current_id = -1;

        // persistent timer
        if (tnode->interval > 0 && !tnode->removed) {
            while (tnode->exec_msec <= now_msec) {
                tnode->exec_msec += tnode->interval;
            }
            swHeap_change_priority(timer->heap, tnode->exec_msec, tmp);
            continue;
        }

        timer->num--;
        swHeap_pop(timer->heap);
        timer->map->erase(tnode->id);
        sw_free(tnode);
    }

    if (!tnode || !tmp) {
        timer->_next_msec = -1;
        timer->set(timer, -1);
    } else {
        long next_msec = tnode->exec_msec - now_msec;
        if (next_msec <= 0) {
            next_msec = 1;
        }
        timer->set(timer, next_msec);
    }
    timer->round++;

    return SW_OK;
}
