#include "coroutine.h"
#include "context.h"
#include <map>

using namespace swoole;

struct coroutine_s
{
    Context *ctx;
    int cid;
};

static struct
{
    int stack_size;
    int current_cid;
    struct coroutine_s *coroutines[MAX_CORO_NUM_LIMIT];
    coroutine_close_t onClose;
} swCoroG =
{ SW_DEFAULT_C_STACK_SIZE, -1,
{ NULL, }, NULL};

#ifndef SW_USE_LIBCO

int coroutine_create(coroutine_func_t fn, void* args)
{
    int cid = alloc_cidmap();
    if (unlikely(cid == -1))
    {
        swWarn("alloc_cidmap failed");
        return CORO_LIMIT;
    }

    coroutine_t *co = new coroutine_t;
    co->ctx = new Context(swCoroG.stack_size, fn, args);
    co->cid = cid;
    swCoroG.coroutines[cid] = co;
    swCoroG.current_cid = cid;
    co->ctx->SwapIn();
    if (co->ctx->end)
    {
        if (swCoroG.onClose)
        {
            swCoroG.onClose();
        }
        coroutine_release(co);
    }
    return cid;
}

void coroutine_yield(coroutine_t *co)
{
    swCoroG.current_cid = -1;
    co->ctx->SwapOut();
}

void coroutine_resume(coroutine_t *co)
{
    swCoroG.current_cid = co->cid;
    co->ctx->SwapIn();
    if (co->ctx->end)
    {
        if (swCoroG.onClose)
        {
            swCoroG.onClose();
        }
        coroutine_release(co);
    }
}

void coroutine_release(coroutine_t *co)
{
    free_cidmap(co->cid);
    swCoroG.coroutines[co->cid] = NULL;
    delete co->ctx;
    delete co;
}

void coroutine_set_close(coroutine_close_t func)
{
    swCoroG.onClose = func;
}

coroutine_t* coroutine_get_by_id(int cid)
{
    return swCoroG.coroutines[cid];
}

int coroutine_get_cid()
{
    return swCoroG.current_cid;
}

#endif
