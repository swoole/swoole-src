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

enum channel_coroutine_type
{
    PRODUCER = 1,
    CONSUMER = 2,
};

class Channel;

struct notify_msg_t
{
    Channel *chan;
    coroutine_t *co;
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

public:
    int binding_cid;
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

    Channel(size_t _capacity);
    void yield(enum channel_coroutine_type type);
    void notify(enum channel_coroutine_type type);
    void* pop(double timeout = 0);
    bool push(void *data);
    bool close();
};

};

