#include "channel.h"

using namespace swoole;

Channel::Channel(size_t _capacity)
{
    capacity = _capacity;
    closed = false;
    binding_cid = 0;

    if (SwooleG.chan_pipe == NULL)
    {
        SwooleG.chan_pipe = (swPipe *) sw_malloc(sizeof(swPipe));
        if (swPipeNotify_auto(SwooleG.chan_pipe, 1, 1) < 0)
        {
            swError("failed to create eventfd.");
        }
        swReactor_setHandle(SwooleG.main_reactor, SW_FD_CHAN_PIPE, channel_onNotify);
    }
}

void Channel::yield(enum channel_coroutine_type type)
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

void Channel::notify(enum channel_coroutine_type type)
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

    binding_cid = coroutine_get_cid(co);
    notify_msg_t *msg = new notify_msg_t;
    msg->chan = this;
    msg->co = co;
    SwooleG.main_reactor->defer(SwooleG.main_reactor, channel_defer_callback, msg);
    int pfd = SwooleG.chan_pipe->getFd(SwooleG.chan_pipe, 0);
    swConnection *_socket = swReactor_get(SwooleG.main_reactor, pfd);
    if (_socket && _socket->events == 0)
    {
        SwooleG.main_reactor->add(SwooleG.main_reactor, pfd, SW_FD_CHAN_PIPE | SW_EVENT_READ);
    }
    uint64_t flag = 1;
    SwooleG.chan_pipe->write(SwooleG.chan_pipe, &flag, sizeof(flag));
}

void* Channel::pop(double timeout)
{
    if (is_empty() || (binding_cid && (binding_cid != coroutine_get_current_cid())))
    {
        yield(CONSUMER);
    }
    void *data = data_queue.front();
    data_queue.pop();
    if (binding_cid == 0 && producer_queue.size() > 0)
    {
        notify(PRODUCER);
    }
    return data;
}

bool Channel::push(void *data)
{
    if (is_full() && (binding_cid && binding_cid != coroutine_get_current_cid()))
    {
        yield(PRODUCER);
    }
    data_queue.push(data);
    if (binding_cid == 0 && consumer_queue.size() > 0)
    {
        notify(CONSUMER);
    }
    return true;
}
