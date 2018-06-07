#include "php_swoole.h"

#ifdef SW_COROUTINE
#ifdef SW_USE_LIBCO
#include "coroutine.h"
#include "thirdparty/libco/co_routine.h"
#include "thirdparty/libco/co_routine_inner.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct coroutine_s
{
    stCoRoutine_t* rep;
    int cid;
    coroutine_close_t onClose;
};

static struct
{
    int current_cid;
    struct coroutine_s *coroutines[MAX_CORO_NUM_LIMIT];
    coroutine_close_t onClose;
} swCoroG = { -1,{ NULL, }, NULL};

void coroutine_release(coroutine_t *co)
{
    stCoRoutine_t *_co = co->rep;
    co_release(_co);
}

void coroutine_resume(coroutine_t *co)
{
    stCoRoutine_t *_co = co->rep;
    swCoroG.current_cid = co->cid;
    co_resume(_co);
    if (_co->cEnd)
    {
        if (swCoroG.onClose)
        {
            swCoroG.onClose();
        }
        coroutine_release(co);
    }
}

int coroutine_create(coroutine_func_t func, void* args)
{
    int cid = alloc_cidmap();
    if (unlikely(cid == -1))
    {
        return CORO_LIMIT;
    }
    stCoRoutine_t* _co = NULL;
    stCoRoutineAttr_t attr;
    attr.stack_size = SW_DEFAULT_C_STACK_SIZE;
    co_create(&_co, &attr, func, args);

    coroutine_t* coro = new coroutine_t;
    coro->rep = _co;
    coro->cid = cid;

    swCoroG.coroutines[cid] = coro;
    swCoroG.current_cid = cid;

    coroutine_resume(coro);
    return cid;
}

void coroutine_yield(coroutine_t *co)
{
    stCoRoutine_t *_co = co->rep;
    swCoroG.current_cid = -1;
    co_yield(_co);
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

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif
#endif
