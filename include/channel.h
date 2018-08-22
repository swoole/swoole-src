#pragma once

#include "swoole.h"
#include "context.h"
#include "coroutine.h"
#include <string>
#include <iostream>
#include <queue>
#include <sys/stat.h>

namespace swoole {

static int channel_onNotify(swReactor *reactor, swEvent *event);
static void channel_defer_callback(void *data);

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

class Channel
{
private:
    std::queue<coroutine_t *> producer_queue;
    std::queue<coroutine_t *> consumer_queue;
    std::queue<void *> data_queue;
    size_t capacity;
    bool closed;

public:
    int binding_cid;
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

    Channel(size_t _capacity);
    void yield(enum channel_coroutine_type type);
    void notify(enum channel_coroutine_type type);
    void* pop(double timeout = 0);
    bool push(void *data);
};

static int channel_onNotify(swReactor *reactor, swEvent *event)
{
    uint64_t notify;
    while (read(SwooleG.chan_pipe->getFd(SwooleG.chan_pipe, 0), &notify, sizeof(notify)) > 0);
    return 0;
}

static void channel_defer_callback(void *data)
{
    notify_msg_t *msg = (notify_msg_t *) data;
    msg->chan->binding_cid = 0;
    swDebug("resume[%d]", coroutine_get_cid(msg->co));
    coroutine_resume(msg->co);
    delete msg;
}

};

