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
#include <string>

/* allocate cid for coroutine */
typedef struct cidmap
{
    uint32_t nr_free;
    char page[65536];
} cidmap_t;

using namespace swoole;

struct coroutine_s
{
public:
    Context ctx;
    int cid;
    void *task;
    coroutine_s(int _cid, size_t stack_size, coroutine_func_t fn, void *private_data) :
            ctx(stack_size, fn, private_data)
    {
        cid = _cid;
        task = NULL;
    }
};

static struct
{
    int                 stack_size;
    int                 call_stack_size;
    struct coroutine_s* coroutines[MAX_CORO_NUM_LIMIT + 1];
    struct coroutine_s* call_stack[SW_MAX_CORO_NESTING_LEVEL];
    coro_php_yield_t    onYield;  /* before php yield coro */
    coro_php_resume_t   onResume; /* before php resume coro */
    coro_php_close_t    onClose;  /* before php close coro */
} swCoroG = { SW_DEFAULT_C_STACK_SIZE, 0, { nullptr, },  { nullptr, }, nullptr, nullptr, nullptr };

/* 1 <= cid <= 524288 */
static cidmap_t cidmap =
{ MAX_CORO_NUM_LIMIT,
{ 0 } };

static int last_cid = -1;

static inline int test_and_set_bit(int cid, void *addr)
{
    uint32_t mask = 1U << (cid & 0x1f);
    uint32_t *p = ((uint32_t*) addr) + (cid >> 5);
    uint32_t old = *p;

    *p = old | mask;

    return (old & mask) == 0;
}

static inline void clear_bit(int cid, void *addr)
{
    uint32_t mask = 1U << (cid & 0x1f);
    uint32_t *p = ((uint32_t*) addr) + (cid >> 5);
    uint32_t old = *p;

    *p = old & ~mask;
}

/* find next free cid */
static inline int find_next_zero_bit(void *addr, int cid)
{
    uint32_t *p;
    uint32_t mask;
    int mark = cid;

    cid++;
    cid &= 0x7ffff;
    while (cid != mark)
    {
        mask = 1U << (cid & 0x1f);
        p = ((uint32_t*) addr) + (cid >> 5);

        if ((~(*p) & mask))
        {
            break;
        }
        ++cid;
        cid &= 0x7ffff;
    }

    return cid;
}

static inline int alloc_cidmap()
{
    int cid;

    if (cidmap.nr_free == 0)
    {
        return -1;
    }

    cid = find_next_zero_bit(&cidmap.page, last_cid);
    if (test_and_set_bit(cid, &cidmap.page))
    {
        --cidmap.nr_free;
        last_cid = cid;
        return cid + 1;
    }

    return -1;
}

static inline void free_cidmap(int cid)
{
    cid--;
    cidmap.nr_free++;
    clear_bit(cid, &cidmap.page);
}

int coroutine_create(coroutine_func_t fn, void* args)
{
    int cid = alloc_cidmap();
    if (unlikely(cid == -1))
    {
        swWarn("alloc_cidmap failed");
        return CORO_LIMIT;
    }

    coroutine_t *co = new coroutine_s(cid, swCoroG.stack_size, fn, args);
    swCoroG.coroutines[cid] = co;
    swCoroG.call_stack[swCoroG.call_stack_size++] = co;
    co->ctx.SwapIn();
    if (co->ctx.end)
    {
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
    co->ctx.SwapOut();
}

void coroutine_resume(coroutine_t *co)
{
    if (swCoroG.onResume)
    {
        swCoroG.onResume(co->task);
    }
    swCoroG.call_stack[swCoroG.call_stack_size++] = co;
    co->ctx.SwapIn();
    if (co->ctx.end)
    {
        coroutine_release(co);
    }
}

void coroutine_yield_naked(coroutine_t *co)
{
    swCoroG.call_stack_size--;
    co->ctx.SwapOut();
}

void coroutine_resume_naked(coroutine_t *co)
{
    swCoroG.call_stack[swCoroG.call_stack_size++] = co;
    co->ctx.SwapIn();
    if (co->ctx.end)
    {
        coroutine_release(co);
    }
}

void coroutine_release(coroutine_t *co)
{
    if (swCoroG.onClose)
    {
        swCoroG.onClose();
    }
    free_cidmap(co->cid);
    swCoroG.call_stack_size--;
    swCoroG.coroutines[co->cid] = NULL;
    delete co;
}

void coroutine_set_task(coroutine_t *co, void *task)
{
    co->task = task;
}

void* coroutine_get_task_by_cid(int cid)
{
    coroutine_t *co = swCoroG.coroutines[cid];
    if (co == nullptr)
    {
        return nullptr;
    }
    else
    {
        return co->task;
    }
}

coroutine_t* coroutine_get_by_id(int cid)
{
    return swCoroG.coroutines[cid];
}

coroutine_t* coroutine_get_current()
{
    return (swCoroG.call_stack_size > 0) ? swCoroG.call_stack[swCoroG.call_stack_size - 1] : nullptr;
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

int coroutine_get_current_cid()
{
    coroutine_t* co = coroutine_get_current();
    if (co)
    {
        return co->cid;
    }
    else
    {
        return -1;
    }
}

int coroutine_get_cid(coroutine_t *co)
{
    return co->cid;
}

int coroutine_test_alloc_cid()
{
    int cid = alloc_cidmap();
    if (unlikely(cid == -1))
    {
        swWarn("alloc_cidmap failed");
        return CORO_LIMIT;
    }
    return cid;
}

void coroutine_test_free_cid(int cid)
{
    free_cidmap(cid);
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

