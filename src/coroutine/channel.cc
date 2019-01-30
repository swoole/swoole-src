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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "channel.h"

#include <unordered_map>

using namespace swoole;

void Channel::timer_callback(swTimer *timer, swTimer_node *tnode)
{
    msg_t *msg = (msg_t *) tnode->data;
    msg->error = true;
    msg->timer = nullptr;
    msg->chan->remove(msg->type, msg->co);
    msg->co->resume();
}

void Channel::cancel_callback(void *data)
{
    msg_t *msg = (msg_t *) data;
    msg->error = true;
    msg->chan->remove(msg->type, msg->co);
}

bool Channel::wait(msg_t *msg)
{
    Coroutine *co = Coroutine::get_current();
    if (unlikely(!co))
    {
        swError("Channel::yield() must be called in the coroutine.");
    }
    if (msg->type == PRODUCER)
    {
        producer_queue.push_back(co);
        swTraceLog(SW_TRACE_CHANNEL, "producer cid=%ld", co->get_cid());
    }
    else // if (msg.type == CONSUMER)
    {
        consumer_queue.push_back(co);
        swTraceLog(SW_TRACE_CHANNEL, "consumer cid=%ld", co->get_cid());
    }
    return co->yield(cancel_callback, msg) && !msg->error && !closed;
}

void* Channel::pop(double timeout)
{
    if (closed)
    {
        return nullptr;
    }
    if (is_empty() || !consumer_queue.empty())
    {
        msg_t msg(this, CONSUMER, timeout);
        if (unlikely(!wait(&msg)))
        {
            return nullptr;
        }
    }
    /**
     * pop data
     */
    void *data = data_queue.front();
    data_queue.pop();
    /**
     * notify producer
     */
    if (!producer_queue.empty())
    {
        Coroutine *co = pop_coroutine(PRODUCER);
        co->resume();
    }
    return data;
}

bool Channel::push(void *data, double timeout)
{
    if (closed)
    {
        return false;
    }
    if (is_full() || !producer_queue.empty())
    {
        msg_t msg(this, PRODUCER, timeout);
        if (unlikely(!wait(&msg)))
        {
            return false;
        }
    }
    /**
     * push data
     */
    data_queue.push(data);
    swTraceLog(SW_TRACE_CHANNEL, "push data to channel, count=%ld", length());
    /**
     * notify consumer
     */
    if (!consumer_queue.empty())
    {
        Coroutine *co = pop_coroutine(CONSUMER);
        co->resume();
    }
    return true;
}

bool Channel::close()
{
    if (closed)
    {
        return false;
    }
    swTraceLog(SW_TRACE_CHANNEL, "channel closed");
    closed = true;
    while (!producer_queue.empty())
    {
        Coroutine *co = pop_coroutine(PRODUCER);
        co->resume();
    }
    while (!consumer_queue.empty())
    {
        Coroutine *co = pop_coroutine(CONSUMER);
        co->resume();
    }
    return true;
}
