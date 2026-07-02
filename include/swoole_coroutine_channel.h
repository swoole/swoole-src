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
#include <algorithm>
#include <deque>
#include <memory>
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

    explicit ChannelBase(size_t _capacity = 1) : capacity(_capacity == 0 ? 1 : _capacity) {}

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
    std::deque<Coroutine *> producer_queue;
    std::deque<Coroutine *> consumer_queue;

    static void timer_callback(Timer *timer, TimerNode *tnode);
    static void log_discarded(const char *type, size_t count);

    void yield(Opcode type);

    void consumer_remove(Coroutine *co) {
        consumer_queue.erase(std::remove(consumer_queue.begin(), consumer_queue.end(), co), consumer_queue.end());
    }

    void producer_remove(Coroutine *co) {
        producer_queue.erase(std::remove(producer_queue.begin(), producer_queue.end(), co), producer_queue.end());
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
    explicit ChannelImpl(size_t _capacity = 1) : ChannelBase(_capacity), data_queue(new T[capacity]) {
        if ((capacity & (capacity - 1)) == 0) {
            mask_ = capacity - 1;
        }
    }

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
        if (sw_unlikely(!ChannelBase::wait_push(is_full(), timeout))) {
            return false;
        }
        return push_data(std::move(data));
    }

    bool wait_push(double timeout = -1) {
        return ChannelBase::wait_push(is_full(), timeout);
    }

    bool push_data(T data) {
        if (sw_unlikely(is_full())) {
            error_ = ERROR_TIMEOUT;
            return false;
        }
        data_queue[tail_] = std::move(data);
        tail_ = next(tail_);
        count_++;
        swoole_trace_log(SW_TRACE_CHANNEL, "push data to channel, count=%ld", length());
        notify_consumer();
        return true;
    }

    bool is_empty() const {
        return count_ == 0;
    }

    bool is_full() const {
        return count_ == capacity;
    }

    size_t length() const {
        return count_;
    }

    bool pop_data(T *data) {
        if (sw_unlikely(count_ == 0)) {
            return false;
        }
        *data = std::move(data_queue[head_]);
        head_ = next(head_);
        count_--;
        return true;
    }

  protected:
    size_t next(size_t offset) const {
        return mask_ ? (offset + 1) & mask_ : (++offset == capacity ? 0 : offset);
    }

    std::unique_ptr<T[]> data_queue;
    size_t head_ = 0;
    size_t tail_ = 0;
    size_t count_ = 0;
    size_t mask_ = 0;
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
