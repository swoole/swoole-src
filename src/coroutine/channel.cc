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

void Channel::timer_callback(Timer *timer, TimerNode *tnode) {
    TimeoutMessage *msg = (TimeoutMessage *) tnode->data;
    msg->error = true;
    msg->timer = nullptr;
    if (msg->type == CONSUMER) {
        msg->chan->consumer_remove(msg->co);
    } else {
        msg->chan->producer_remove(msg->co);
    }
    msg->co->resume();
}

void Channel::yield(enum Opcode type) {
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

void *Channel::pop(double timeout) {
    Coroutine *current_co = Coroutine::get_current_safe();
    if (closed && is_empty()) {
        error_ = ERROR_CLOSED;
        return nullptr;
    }
    if (is_empty() || !consumer_queue.empty()) {
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
        if (current_co->is_canceled()) {
            error_ = ERROR_CANCELED;
            return nullptr;
        }
        if (msg.error) {
            error_ = ERROR_TIMEOUT;
            return nullptr;
        }
        if (closed && is_empty()) {
            error_ = ERROR_CLOSED;
            return nullptr;
        }
    }
    /**
     * pop data
     */
    void *data = data_queue.front();
    data_queue.pop();
    /**
     * notify producer
     */
    if (!producer_queue.empty()) {
        Coroutine *co = pop_coroutine(PRODUCER);
        co->resume();
    }
    return data;
}

bool Channel::push(void *data, double timeout) {
    Coroutine *current_co = Coroutine::get_current_safe();
    if (closed) {
        error_ = ERROR_CLOSED;
        return false;
    }
    if (is_full() || !producer_queue.empty()) {
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
        if (current_co->is_canceled()) {
            error_ = ERROR_CANCELED;
            return false;
        }
        if (msg.error) {
            error_ = ERROR_TIMEOUT;
            return false;
        }
        if (closed) {
            error_ = ERROR_CLOSED;
            return false;
        }
    }
    /**
     * push data
     */
    data_queue.push(data);
    swoole_trace_log(SW_TRACE_CHANNEL, "push data to channel, count=%ld", length());
    /**
     * notify consumer
     */
    if (!consumer_queue.empty()) {
        Coroutine *co = pop_coroutine(CONSUMER);
        co->resume();
    }
    return true;
}

bool Channel::close() {
    if (closed) {
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
