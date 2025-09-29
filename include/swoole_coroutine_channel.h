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
#include "swoole_coroutine.h"

#include <iostream>
#include <string>
#include <list>
#include <queue>

namespace swoole {
namespace coroutine {
//-------------------------------------------------------------------------------
class Channel {
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
        Channel *chan;
        Opcode type;
        Coroutine *co;
        bool error;
        TimerNode *timer;
    };

    void *pop(double timeout = -1);
    bool push(void *data, double timeout = -1);
    bool close();

    explicit Channel(size_t _capacity = 1) : capacity(_capacity) {}

    ~Channel() {
        if (!producer_queue.empty()) {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_CO_HAS_BEEN_DISCARDED,
                             "channel is destroyed, %zu producers will be discarded",
                             producer_queue.size());
        }
        if (!consumer_queue.empty()) {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_CO_HAS_BEEN_DISCARDED,
                             "channel is destroyed, %zu consumers will be discarded",
                             consumer_queue.size());
        }
    }

    bool is_closed() const {
        return closed;
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

    size_t consumer_num() const {
        return consumer_queue.size();
    }

    size_t producer_num() const {
        return producer_queue.size();
    }

    void *pop_data() {
        if (data_queue.empty()) {
            return nullptr;
        }
        void *data = data_queue.front();
        data_queue.pop();
        return data;
    }

    int get_error() const {
        return error_;
    }

  protected:
    size_t capacity = 1;
    bool closed = false;
    int error_ = 0;
    std::list<Coroutine *> producer_queue;
    std::list<Coroutine *> consumer_queue;
    std::queue<void *> data_queue;

    static void timer_callback(Timer *timer, TimerNode *tnode);

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
//-------------------------------------------------------------------------------
}  // namespace coroutine
}  // namespace swoole
