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

#include "swoole_coroutine.h"

#include <iostream>
#include <string>
#include <list>
#include <queue>
#include <utility>

namespace swoole {
namespace coroutine {
//-------------------------------------------------------------------------------
class ChannelBase {
  public:
    enum Opcode {
        PRODUCER = 1,
        CONSUMER = 2,
    };

    enum ErrorCode {
        ERROR_OK = 0,
        ERROR_TIMEOUT = -1,
        ERROR_CLOSED = -2,
        ERROR_CANCELED = -3,
    };

    struct TimeoutMessage {
        ChannelBase *chan;
        Opcode type;
        Coroutine *co;
        bool error;
        TimerNode *timer;
    };

    explicit ChannelBase(size_t _capacity = 1) : capacity(_capacity) {}

    ~ChannelBase();

    bool is_closed() const {
        return closed;
    }

    bool close();

    bool wait_push(bool full, double timeout = -1);
    bool wait_pop(bool empty, double timeout = -1);

    size_t consumer_num() const {
        return consumer_queue.size();
    }

    size_t producer_num() const {
        return producer_queue.size();
    }

    int get_error() const {
        return error_;
    }

  protected:
    void notify_consumer();
    void notify_producer();

    size_t capacity = 1;
    bool closed = false;
    int error_ = 0;
    std::list<Coroutine *> producer_queue;
    std::list<Coroutine *> consumer_queue;

    static void timer_callback(Timer *timer, TimerNode *tnode);
    static void log_discarded(const char *type, size_t count);

    void yield(Opcode type);

    void consumer_remove(Coroutine *co) {
        consumer_queue.remove(co);
    }

    void producer_remove(Coroutine *co) {
        producer_queue.remove(co);
    }

    Coroutine *pop_coroutine(Opcode type) {
        Coroutine *co;
        if (type == PRODUCER) {
            co = producer_queue.front();
            producer_queue.pop_front();
            swoole_trace_log(SW_TRACE_CHANNEL, "resume producer cid=%ld", co->get_cid());
        } else  // if (type == CONSUMER)
        {
            co = consumer_queue.front();
            consumer_queue.pop_front();
            swoole_trace_log(SW_TRACE_CHANNEL, "resume consumer cid=%ld", co->get_cid());
        }
        return co;
    }
};

template <typename T>
class ChannelImpl : public ChannelBase {
  public:
    using ChannelBase::ChannelBase;

    bool pop(T *data, double timeout = -1) {
        if (sw_unlikely(!wait_pop(is_empty(), timeout))) {
            return false;
        }
        if (sw_unlikely(closed && is_empty())) {
            error_ = ERROR_CLOSED;
            return false;
        }
        if (sw_unlikely(!pop_data(data))) {
            return false;
        }
        notify_producer();
        return true;
    }

    bool push(T data, double timeout = -1) {
        if (sw_unlikely(!wait_push(is_full(), timeout))) {
            return false;
        }
        push_data(std::move(data));
        return true;
    }

    bool wait_push(double timeout = -1) {
        return ChannelBase::wait_push(is_full(), timeout);
    }

    void push_data(T data) {
        data_queue.push(std::move(data));
        swoole_trace_log(SW_TRACE_CHANNEL, "push data to channel, count=%ld", length());
        notify_consumer();
    }

    bool is_empty() const {
        return data_queue.empty();
    }

    bool is_full() const {
        return data_queue.size() == capacity;
    }

    size_t length() const {
        return data_queue.size();
    }

    bool pop_data(T *data) {
        if (sw_unlikely(data_queue.empty())) {
            return false;
        }
        *data = std::move(data_queue.front());
        data_queue.pop();
        return true;
    }

  protected:
    std::queue<T> data_queue;
};

class Channel : public ChannelImpl<void *> {
  public:
    using ChannelImpl<void *>::ChannelImpl;

    void *pop(double timeout = -1) {
        void *data = nullptr;
        return ChannelImpl<void *>::pop(&data, timeout) ? data : nullptr;
    }

    void *pop_data() {
        void *data = nullptr;
        return ChannelImpl<void *>::pop_data(&data) ? data : nullptr;
    }
};
//-------------------------------------------------------------------------------
}  // namespace coroutine
}  // namespace swoole
