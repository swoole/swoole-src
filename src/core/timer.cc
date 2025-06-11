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
 +----------------------------------------------------------------------+
 */

#include "swoole_api.h"
#include "swoole_reactor.h"
#include "swoole_timer.h"

namespace swoole {
Timer::Timer(bool manually_trigger) : heap(1024, Heap::MIN_HEAP) {
    _current_id = -1;
    next_msec_ = -1;
    _next_id = 1;
    round = 0;
    base_time = get_absolute_msec();
    init(manually_trigger);
}

void Timer::init(bool manually_trigger) {
    if (manually_trigger) {
        set = [](Timer *, long) -> int { return SW_OK; };
        close = [](Timer *) { };
        return;
    }
    if (SwooleTG.reactor) {
        init_with_reactor(SwooleTG.reactor);
    } else {
        init_with_system_timer();
    }
}

void Timer::release_node(TimerNode *tnode) {
    if (tnode->destructor) {
        tnode->destructor(tnode);
    }
    delete tnode;
}

void Timer::init_with_reactor(Reactor *reactor) {
    reactor_ = reactor;
    set = [](Timer *timer, long exec_msec) -> int {
        timer->reactor_->timeout_msec = exec_msec;
        return SW_OK;
    };
    close = [](Timer *timer) { timer->set(timer, -1); };

    reactor->set_end_callback(Reactor::PRIORITY_TIMER, [this](Reactor *) { select(); });

    reactor->set_exit_condition(Reactor::EXIT_CONDITION_TIMER,
                                [this](Reactor *reactor, size_t &event_num) -> bool { return count() == 0; });

    reactor->add_destroy_callback([](void *) {
        if (swoole_timer_is_available()) {
            swoole_timer_free();
        }
    });
}

void Timer::reinit(bool manually_trigger) {
    close(this);
    init(manually_trigger);
    set(this, next_msec_);
}

Timer::~Timer() {
    if (close) {
        close(this);
    }
    for (const auto &iter : map) {
        release_node(iter.second);
    }
}

TimerNode *Timer::add(long _msec, bool persistent, void *data, const TimerCallback &callback) {
    if (sw_unlikely(_msec <= 0)) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_INVALID_PARAMS, "msec value[%ld] is invalid", _msec);
        return nullptr;
    }

    int64_t now_msec = get_relative_msec();
    if (sw_unlikely(now_msec < 0)) {
        return nullptr;
    }

    auto *tnode = new TimerNode();
    tnode->id = _next_id++;
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

    tnode->heap_node = heap.push(tnode->exec_msec, tnode);
    if (sw_unlikely(tnode->heap_node == nullptr)) {
        release_node(tnode);
        return nullptr;
    }
    map.emplace(tnode->id, tnode);
    swoole_trace_log(SW_TRACE_TIMER,
                     "id=%ld, exec_msec=%" PRId64 ", msec=%ld, round=%" PRIu64 ", exist=%lu",
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
        swoole_trace_log(SW_TRACE_TIMER,
                         "set-remove: id=%ld, exec_msec=%" PRId64 ", round=%" PRIu64 ", exist=%lu",
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
        heap.remove(tnode->heap_node);
    }
    swoole_trace_log(SW_TRACE_TIMER,
                     "id=%ld, exec_msec=%" PRId64 ", round=%" PRIu64 ", exist=%lu",
                     tnode->id,
                     tnode->exec_msec,
                     tnode->round,
                     count());
    release_node(tnode);
    return true;
}

int Timer::select() {
    int64_t now_msec = get_relative_msec();
    if (sw_unlikely(now_msec < 0)) {
        return SW_ERR;
    }

    TimerNode *tnode = nullptr;
    HeapNode *tmp;

    swoole_trace_log(SW_TRACE_TIMER, "select begin: now_msec=%" PRId64 ", round=%" PRId64, now_msec, round);

    while ((tmp = heap.top())) {
        tnode = (TimerNode *) tmp->data;
        if (tnode->exec_msec > now_msec || tnode->round == round) {
            break;
        }

        _current_id = tnode->id;
        if (!tnode->removed) {
            swoole_trace_log(SW_TRACE_TIMER,
                             "execute callback [id=%ld, exec_msec=%" PRId64 ", round=%" PRIu64 ", exist=%lu]",
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
            tnode->exec_count++;
            heap.change_priority(tnode->exec_msec, tmp);
            continue;
        }

        heap.pop();
        map.erase(tnode->id);
        release_node(tnode);
        tnode = nullptr;
    }

    if (!tnode || !tmp) {
        next_msec_ = -1;
        set(this, -1);
    } else {
        next_msec_ = tnode->exec_msec - now_msec;
        if (next_msec_ <= 0) {
            next_msec_ = 1;
        }
        set(this, next_msec_);
    }
    round++;

    return SW_OK;
}
};  // namespace swoole
