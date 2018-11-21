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
#include "context.h"

#include <unordered_map>
#include <string>

using namespace swoole;

struct coroutine_s
{
public:
    Context ctx;
    long cid;
    sw_coro_state state;
    void *task;
    coroutine_s(long _cid, size_t stack_size, coroutine_func_t fn, void *private_data) :
            ctx(stack_size, fn, private_data)
    {
        cid = _cid;
        task = NULL;
        state = SW_CORO_INIT;
    }
};

static struct
{
    int                 stack_size;
    int                 call_stack_size;
    long                last_cid;
    struct coroutine_s* call_stack[SW_MAX_CORO_NESTING_LEVEL];
    coro_php_yield_t    onYield;  /* before php yield coro */
    coro_php_resume_t   onResume; /* before php resume coro */
    coro_php_close_t    onClose;  /* before php close coro */
} swCoroG = { SW_DEFAULT_C_STACK_SIZE, 0, 1, { nullptr, }, nullptr, nullptr, nullptr };

static std::unordered_map<long, coroutine_s*> coroutines;

long coroutine_create(coroutine_func_t fn, void* args)
{
    if (unlikely(swCoroG.call_stack_size == SW_MAX_CORO_NESTING_LEVEL))
    {
        swWarn("reaches the max coroutine nesting level %d", SW_MAX_CORO_NESTING_LEVEL);
        return CORO_LIMIT;
    }
    long cid = swCoroG.last_cid++;
    coroutine_t *co = new coroutine_s(cid, swCoroG.stack_size, fn, args);
    coroutines[cid] = co;
    swCoroG.call_stack[swCoroG.call_stack_size++] = co;
    co->state = SW_CORO_RUNNING;
    co->ctx.SwapIn();
    if (co->ctx.end)
    {
        co->state = SW_CORO_END;
        coroutine_release(co);
    }
    return cid;
}

void coroutine_yield(coroutine_t *co)
{
    if (swCoroG.onYield)
    {
        swCoroG.onYield(co->task);
    }
    swCoroG.call_stack_size--;
    co->state = SW_CORO_YIELD;
    co->ctx.SwapOut();
}

void coroutine_resume(coroutine_t *co)
{
    if (swCoroG.onResume)
    {
        swCoroG.onResume(co->task);
    }
    swCoroG.call_stack[swCoroG.call_stack_size++] = co;
    co->state = SW_CORO_RUNNING;
    co->ctx.SwapIn();
    if (co->ctx.end)
    {
        coroutine_release(co);
    }
}

void coroutine_yield_naked(coroutine_t *co)
{
    swCoroG.call_stack_size--;
    co->state = SW_CORO_YIELD;
    co->ctx.SwapOut();
}

void coroutine_resume_naked(coroutine_t *co)
{
    swCoroG.call_stack[swCoroG.call_stack_size++] = co;
    co->state = SW_CORO_RUNNING;
    co->ctx.SwapIn();
    if (co->ctx.end)
    {
        coroutine_release(co);
    }
}

void coroutine_release(coroutine_t *co)
{
    co->state = SW_CORO_END;
    if (swCoroG.onClose)
    {
        swCoroG.onClose();
    }
    swCoroG.call_stack_size--;
    coroutines.erase(co->cid);
    delete co;
}

void coroutine_set_task(coroutine_t *co, void *task)
{
    co->task = task;
}

void* coroutine_get_task_by_cid(long cid)
{
    coroutine_t *co = coroutine_get_by_id(cid);
    if (co == nullptr)
    {
        return nullptr;
    }
    else
    {
        return co->task;
    }
}

coroutine_t* coroutine_get_by_id(long cid)
{
    std::unordered_map<long, coroutine_s*>::iterator i = coroutines.find(cid);
    if (i == coroutines.end())
    {
        return nullptr;
    }
    else
    {
        return i->second;
    }
}

coroutine_t* coroutine_get_current()
{
    return likely(swCoroG.call_stack_size > 0) ? swCoroG.call_stack[swCoroG.call_stack_size - 1] : nullptr;
}

void* coroutine_get_current_task()
{
    coroutine_t* co = coroutine_get_current();
    if (co == nullptr)
    {
        return nullptr;
    }
    else
    {
        return co->task;
    }
}

long coroutine_get_current_cid()
{
    coroutine_t* co = coroutine_get_current();
    return likely(co) ? co->cid : -1;
}

long coroutine_get_cid(coroutine_t *co)
{
    return likely(co) ? co->cid : -1;
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
