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

#include "swoole_coroutine_channel.h"

namespace swoole {
namespace coroutine {

ChannelBase::~ChannelBase() {
    if (sw_unlikely(!producer_queue.empty())) {
        log_discarded("producers", producer_queue.size());
    }
    if (sw_unlikely(!consumer_queue.empty())) {
        log_discarded("consumers", consumer_queue.size());
    }
}

void ChannelBase::timer_callback(Timer *timer, TimerNode *tnode) {
    auto *msg = static_cast<TimeoutMessage *>(tnode->data);
    msg->error = true;
    msg->timer = nullptr;
    if (msg->type == CONSUMER) {
        msg->chan->consumer_remove(msg->co);
    } else {
        msg->chan->producer_remove(msg->co);
    }
    msg->co->resume();
}

void ChannelBase::log_discarded(const char *type, size_t count) {
    swoole_set_last_error(SW_ERROR_CO_HAS_BEEN_DISCARDED);
    if (sw_unlikely(SW_LOG_WARNING >= swoole_get_log_level() &&
                    !swoole_is_ignored_error(SW_ERROR_CO_HAS_BEEN_DISCARDED))) {
        size_t len = sw_snprintf(sw_error,
                                 SW_ERROR_MSG_SIZE,
                                 "Channel::~Channel() (ERRNO %d): channel is destroyed, %zu %s will be discarded",
                                 SW_ERROR_CO_HAS_BEEN_DISCARDED,
                                 count,
                                 type);
        sw_logger()->put(SW_LOG_WARNING, sw_error, len);
    }
}

void ChannelBase::yield(Opcode type) {
    Coroutine *co = Coroutine::get_current_safe();
    if (type == PRODUCER) {
        producer_queue.push_back(co);
        swoole_trace_log(SW_TRACE_CHANNEL, "producer cid=%ld", co->get_cid());
    } else {
        consumer_queue.push_back(co);
        swoole_trace_log(SW_TRACE_CHANNEL, "consumer cid=%ld", co->get_cid());
    }
    Coroutine::CancelFunc cancel_fn = [this, type](Coroutine *co) {
        if (type == CONSUMER) {
            consumer_remove(co);
        } else {
            producer_remove(co);
        }
        co->resume();
        return true;
    };
    co->yield(&cancel_fn);
}

bool ChannelBase::wait_pop(bool empty, double timeout) {
    Coroutine *current_co = Coroutine::get_current_safe();
    if (sw_unlikely(closed && empty)) {
        error_ = ERROR_CLOSED;
        return false;
    }
    if (empty || !consumer_queue.empty()) {
        TimeoutMessage msg;
        msg.error = false;
        msg.timer = nullptr;
        if (timeout > 0) {
            msg.chan = this;
            msg.type = CONSUMER;
            msg.co = current_co;
            msg.timer = swoole_timer_add(timeout, false, timer_callback, &msg);
        }

        yield(CONSUMER);

        if (msg.timer) {
            swoole_timer_del(msg.timer);
        }
        if (sw_unlikely(current_co->is_canceled())) {
            error_ = ERROR_CANCELED;
            return false;
        }
        if (sw_unlikely(msg.error)) {
            error_ = ERROR_TIMEOUT;
            return false;
        }
    }
    return true;
}

bool ChannelBase::wait_push(bool full, double timeout) {
    Coroutine *current_co = Coroutine::get_current_safe();
    if (sw_unlikely(closed)) {
        error_ = ERROR_CLOSED;
        return false;
    }
    if (full || !producer_queue.empty()) {
        TimeoutMessage msg;
        msg.error = false;
        msg.timer = nullptr;
        if (timeout > 0) {
            msg.chan = this;
            msg.type = PRODUCER;
            msg.co = current_co;
            msg.timer = swoole_timer_add(timeout, false, timer_callback, &msg);
        }

        yield(PRODUCER);

        if (msg.timer) {
            swoole_timer_del(msg.timer);
        }
        if (sw_unlikely(current_co->is_canceled())) {
            error_ = ERROR_CANCELED;
            return false;
        }
        if (sw_unlikely(msg.error)) {
            error_ = ERROR_TIMEOUT;
            return false;
        }
        if (sw_unlikely(closed)) {
            error_ = ERROR_CLOSED;
            return false;
        }
    }
    return true;
}

void ChannelBase::notify_consumer() {
    if (!consumer_queue.empty()) {
        Coroutine *co = pop_coroutine(CONSUMER);
        co->resume();
    }
}

void ChannelBase::notify_producer() {
    if (!producer_queue.empty()) {
        Coroutine *co = pop_coroutine(PRODUCER);
        co->resume();
    }
}

bool ChannelBase::close() {
    if (sw_unlikely(closed)) {
        return false;
    }
    swoole_trace_log(SW_TRACE_CHANNEL, "channel closed");
    closed = true;
    while (!producer_queue.empty()) {
        Coroutine *co = pop_coroutine(PRODUCER);
        co->resume();
    }
    while (!consumer_queue.empty()) {
        Coroutine *co = pop_coroutine(CONSUMER);
        co->resume();
    }
    return true;
}

}  // namespace coroutine
}  // namespace swoole
