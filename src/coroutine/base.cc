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

#include "coroutine.h"
#include "async.h"

using namespace swoole;

CoroutineG swCoroG;

long Coroutine::create(coroutine_func_t fn, void* args)
{
    if (unlikely(swCoroG.call_stack_size == SW_MAX_CORO_NESTING_LEVEL))
    {
        swWarn("reaches the max coroutine nesting level %d", SW_MAX_CORO_NESTING_LEVEL);
        return CORO_LIMIT;
    }
    long cid = swCoroG.last_cid++;
    Coroutine *co = new Coroutine(cid, swCoroG.stack_size, fn, args);
    swCoroG.coroutines[cid] = co;
    swCoroG.call_stack[swCoroG.call_stack_size++] = co;
    co->ctx.SwapIn();
    if (co->ctx.end)
    {
        co->state = SW_CORO_END;
        co->release();
    }
    return cid;
}

void Coroutine::yield()
{
    state = SW_CORO_WAITING;
    if (swCoroG.onYield)
    {
        swCoroG.onYield(task);
    }
    swCoroG.call_stack_size--;
    ctx.SwapOut();
}

void Coroutine::resume()
{
    state = SW_CORO_RUNNING;
    if (swCoroG.onResume)
    {
        swCoroG.onResume(task);
    }
    swCoroG.call_stack[swCoroG.call_stack_size++] = this;
    ctx.SwapIn();
    if (ctx.end)
    {
        release();
    }
}

void Coroutine::yield_naked()
{
    state = SW_CORO_WAITING;
    swCoroG.call_stack_size--;
    ctx.SwapOut();
}

void Coroutine::resume_naked()
{
    state = SW_CORO_RUNNING;
    swCoroG.call_stack[swCoroG.call_stack_size++] = this;
    ctx.SwapIn();
    if (ctx.end)
    {
        release();
    }
}

void Coroutine::release()
{
    state = SW_CORO_END;
    if (swCoroG.onClose)
    {
        swCoroG.onClose();
    }
    swCoroG.call_stack_size--;
    swCoroG.coroutines.erase(cid);
    delete this;
}

void* coroutine_get_task_by_cid(long cid)
{
    Coroutine *co = coroutine_get_by_id(cid);
    if (co == nullptr)
    {
        return nullptr;
    }
    else
    {
        return co->get_task();
    }
}

Coroutine* coroutine_get_by_id(long cid)
{
    auto coroutine_iterator = swCoroG.coroutines.find(cid);
    if (coroutine_iterator == swCoroG.coroutines.end())
    {
        return nullptr;
    }
    else
    {
        return coroutine_iterator->second;
    }
}

Coroutine* coroutine_get_current()
{
    return likely(swCoroG.call_stack_size > 0) ? swCoroG.call_stack[swCoroG.call_stack_size - 1] : nullptr;
}

void coroutine_print_list()
{
    for (auto i = swCoroG.coroutines.begin(); i != swCoroG.coroutines.end(); i++)
    {
        const char *state;
        switch(i->second->state){
        case SW_CORO_INIT:
            state = "[INIT]";
            break;
        case SW_CORO_WAITING:
            state = "[WAITING]";
            break;
        case SW_CORO_RUNNING:
            state = "[RUNNING]";
            break;
        case SW_CORO_END:
            state = "[END]";
            break;
        default:
            assert(0);
            return;
        }
        printf("Coroutine\t%ld\t%s\n", i->first, state);
    }
}

void* coroutine_get_current_task()
{
    Coroutine* co = coroutine_get_current();
    if (co == nullptr)
    {
        return nullptr;
    }
    else
    {
        return co->get_task();
    }
}

long coroutine_get_current_cid()
{
    Coroutine* co = coroutine_get_current();
    return likely(co) ? co->get_cid() : -1;
}

void coroutine_set_onYield(coro_php_yield_t func)
{
    swCoroG.onYield = func;
}

void coroutine_set_onResume(coro_php_resume_t func)
{
    swCoroG.onResume = func;
}

void coroutine_set_onClose(coro_php_close_t func)
{
    swCoroG.onClose = func;
}

void coroutine_set_stack_size(int stack_size)
{
    swCoroG.stack_size = stack_size;
}
