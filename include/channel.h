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
    coroutine_t *co;
    bool error;
    swTimer_node *timer;
};

class Channel
{
private:
    std::list<coroutine_t *> producer_queue;
    std::list<coroutine_t *> consumer_queue;
    std::queue<void *> data_queue;
    size_t capacity;
    uint32_t notify_producer_count;
    uint32_t notify_consumer_count;

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

    inline void remove(coroutine_t *co)
    {
        consumer_queue.remove(co);
    }

    /**
     * No coroutine scheduling
     */
    inline void* pop_data()
    {
        void *data = data_queue.front();
        if (data)
        {
            data_queue.pop();
        }
        return data;
    }

    inline coroutine_t* pop_coroutine(enum channel_op type)
    {
        coroutine_t* co;
        if (type == PRODUCER)
        {
            co = producer_queue.front();
            producer_queue.pop_front();
            notify_producer_count--;
            swDebug("resume producer[%d]", coroutine_get_cid(co));
        }
        else
        {
            co = consumer_queue.front();
            consumer_queue.pop_front();
            notify_consumer_count--;
            swDebug("resume consumer[%d]", coroutine_get_cid(co));
        }
        return co;
    }

    Channel(size_t _capacity);
    void yield(enum channel_op type);
    void notify(enum channel_op type);
    void* pop(double timeout = 0);
    bool push(void *data);
    bool close();
};

};

