#pragma once

#include "swoole.h"
#include "coroutine.h"

#include <sys/stat.h>

#include <iostream>
#include <string>
#include <list>
#include <queue>

namespace swoole
{
class Channel
{
public:
    enum opcode
    {
        PRODUCER = 1,
        CONSUMER = 2,
    };

    struct msg_t
    {
        Channel *chan;
        enum opcode type;
        Coroutine *co;
        bool error = false;
        swTimer_node *timer = nullptr;

        msg_t(Channel *chan, enum opcode type, double timeout) :
                chan(chan), type(type)
        {
            co = Coroutine::get_current();
            if (timeout > 0)
            {
                timer = swTimer_add(&SwooleG.timer, (long) (timeout * 1000), 0, this, timer_callback);
                if (unlikely(!timer))
                {
                    error = true;
                    return;
                }
            }
        }

        ~msg_t()
        {
            if (timer)
            {
                swTimer_del(&SwooleG.timer, timer);
            }
        }
    };

    void* pop(double timeout = -1);
    bool push(void *data, double timeout = -1);
    bool close();

    Channel(size_t _capacity = 1) :
            capacity(_capacity)
    {
    }

    ~Channel()
    {
        SW_ASSERT(producer_queue.empty() && consumer_queue.empty());
    }

    inline bool is_closed()
    {
        return closed;
    }

    inline bool is_empty()
    {
        return data_queue.size() == 0;
    }

    inline bool is_full()
    {
        return data_queue.size() == capacity;
    }

    inline size_t length()
    {
        return data_queue.size();
    }

    inline size_t consumer_num()
    {
        return consumer_queue.size();
    }

    inline size_t producer_num()
    {
        return producer_queue.size();
    }

    inline void* pop_data()
    {
        if (data_queue.size() == 0)
        {
            return nullptr;
        }
        void *data = data_queue.front();
        data_queue.pop();
        return data;
    }

protected:
    size_t capacity = 1;
    bool closed = false;
    std::list<Coroutine *> producer_queue;
    std::list<Coroutine *> consumer_queue;
    std::queue<void *> data_queue;

    static void timer_callback(swTimer *timer, swTimer_node *tnode);
    static void cancel_callback(void *data);

    bool wait(msg_t *msg);

    inline void consumer_remove(Coroutine *co)
    {
        consumer_queue.remove(co);
    }

    inline void producer_remove(Coroutine *co)
    {
        producer_queue.remove(co);
    }

    inline void remove(enum opcode type, Coroutine *co)
    {
        if (type == CONSUMER)
        {
            consumer_remove(co);
        }
        else
        {
            producer_remove(co);
        }
    }

    inline Coroutine* pop_coroutine(enum opcode type)
    {
        Coroutine* co;
        if (type == PRODUCER)
        {
            co = producer_queue.front();
            producer_queue.pop_front();
            swTraceLog(SW_TRACE_CHANNEL, "resume producer cid=%ld", co->get_cid());
        }
        else // if (type == CONSUMER)
        {
            co = consumer_queue.front();
            consumer_queue.pop_front();
            swTraceLog(SW_TRACE_CHANNEL, "resume consumer cid=%ld", co->get_cid());
        }
        return co;
    }
};
};
