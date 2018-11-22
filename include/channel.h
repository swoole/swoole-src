#pragma once

#include "swoole.h"
#include "context.h"
#include "coroutine.h"
#include <string>
#include <iostream>
#include <list>
#include <queue>
#include <sys/stat.h>

namespace swoole {

enum channel_op
{
    PRODUCER = 1,
    CONSUMER = 2,
};

class Channel;

struct notify_msg_t
{
    Channel *chan;
    enum channel_op type;
};

struct timeout_msg_t
{
    Channel *chan;
    Coroutine *co;
    bool error;
    swTimer_node *timer;
};

class Channel
{
private:
    std::list<Coroutine *> producer_queue;
    std::list<Coroutine *> consumer_queue;
    std::queue<void *> data_queue;
    size_t capacity;

public:
    bool closed;
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

    inline void remove(Coroutine *co)
    {
        consumer_queue.remove(co);
    }

    /**
     * No coroutine scheduling
     */
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

    inline Coroutine* pop_coroutine(enum channel_op type)
    {
        Coroutine* co;
        if (type == PRODUCER)
        {
            co = producer_queue.front();
            producer_queue.pop_front();
            swTraceLog(SW_TRACE_CHANNEL, "resume producer cid=%ld", co->get_cid());
        }
        else
        {
            co = consumer_queue.front();
            consumer_queue.pop_front();
            swTraceLog(SW_TRACE_CHANNEL, "resume consumer cid=%ld", co->get_cid());
        }
        return co;
    }

    Channel(size_t _capacity);
    void yield(enum channel_op type);
    void* pop(double timeout = 0);
    bool push(void *data, double timeout);
    bool close();
};

};
