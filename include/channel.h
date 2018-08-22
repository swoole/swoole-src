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

class Channel
{
public:
    std::queue<coroutine_t *> producer_queue;
    std::queue<coroutine_t *> consumer_queue;
    std::queue<void *> data_queue;
    size_t capacity;
    bool closed;
    
    Channel(size_t _capacity)
    {
        capacity = _capacity;
        closed = false;

        if (SwooleG.chan_pipe == NULL)
        {
            SwooleG.chan_pipe = (swPipe *) sw_malloc(sizeof(swPipe));
            if (swPipeNotify_auto(SwooleG.chan_pipe, 1, 1) < 0)
            {
                swError("failed to create eventfd.");
            }
            swReactor_setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_CHAN_PIPE, channel_onNotify);
        }
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

    void yield(enum channel_coroutine_type type)
    {
        int _cid = coroutine_get_current_cid();
        if (_cid == -1)
        {
            swError("Socket::yield() must be called in the coroutine.");
        }
        coroutine_t *co = coroutine_get_by_id(_cid);
        if (type == PRODUCER)
        {
            producer_queue.push(co);
            swDebug("producer[%d]", coroutine_get_cid(co));
        }
        else
        {
            consumer_queue.push(co);
            swDebug("consumer[%d]", coroutine_get_cid(co));
        }
        coroutine_yield(co);
    }

    void notify(enum channel_coroutine_type type)
    {
        coroutine_t *co;
        if (type == PRODUCER)
        {
            co = producer_queue.front();
            producer_queue.pop();
            swDebug("producer[%d]", coroutine_get_cid(co));
        }
        else
        {
            co = consumer_queue.front();
            consumer_queue.pop();
            swDebug("consumer[%d]", coroutine_get_cid(co));
        }
        SwooleG.main_reactor->defer(SwooleG.main_reactor, channel_defer_callback, co);
        int pfd = SwooleG.chan_pipe->getFd(SwooleG.chan_pipe, 0);
        swConnection *_socket = swReactor_get(SwooleG.main_reactor, pfd);
        if (_socket && _socket->events == 0)
        {
            SwooleG.main_reactor->add(SwooleG.main_reactor, pfd, PHP_SWOOLE_FD_CHAN_PIPE | SW_EVENT_READ);
        }
        uint64_t flag = 1;
        SwooleG.chan_pipe->write(SwooleG.chan_pipe, &flag, sizeof(flag));
    }

    void* pop(double timeout = 0)
    {
        if (is_empty())
        {
            yield(CONSUMER);
        }
        swDebug("length=%ud", length());
        void *data = data_queue.front();
        data_queue.pop();
        if (producer_queue.size() > 0)
        {
            notify(PRODUCER);
        }
        return data;
    }

    bool push(void *data)
    {
        if (is_full())
        {
            yield(PRODUCER);
        }
        data_queue.push(data);
        if (consumer_queue.size() > 0)
        {
            notify(CONSUMER);
        }
        return true;
    }
};

static int channel_onNotify(swReactor *reactor, swEvent *event)
{
    uint64_t notify;
    while (read(SwooleG.chan_pipe->getFd(SwooleG.chan_pipe, 0), &notify, sizeof(notify)) > 0);
    return 0;
}

static void channel_defer_callback(void *data)
{
    coroutine_t *co = (coroutine_t *) data;
    swDebug("resume[%d]", coroutine_get_cid(co));
    coroutine_resume(co);
}

};

