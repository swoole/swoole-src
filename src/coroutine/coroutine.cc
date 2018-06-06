#include "php_swoole.h"

#ifdef SW_COROUTINE
#ifdef SW_USE_LIBCO
#include "coroutine.h"
#include "swoole_coroutine.h"
#include "thirdparty/libco/co_routine.h"
#include "thirdparty/libco/co_routine_inner.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct coroutine_t
{
    stCoRoutine_t* rep;
};

static coroutine_t *g_coroutine_pool[DEFAULT_MAX_CORO_NUM] =
{ 0 };

coroutine_t *get_coroutine_by_id(int cid)
{
    return g_coroutine_pool[cid];
}

void coroutine_release(coroutine_t *co)
{
    stCoRoutine_t *_co = co->rep;
    co_release(_co);
}

void coroutine_resume(coroutine_t *co)
{
    stCoRoutine_t *_co = co->rep;
    co_resume(_co);
    if (_co->cEnd)
    {
        coroutine_release(co);
    }
}

int coroutine_create(php_func_co_t func, php_args args)
{
    if (unlikely(COROG.coro_num >= COROG.max_coro_num) )
    {
        COROG.error = 1;
        swWarn("exceed max number of coro_num %d, max_coro_num:%d", COROG.coro_num, COROG.max_coro_num);
        return CORO_LIMIT;
    }
    int cid = alloc_cidmap();
    if (unlikely(cid == -1))
    {
        COROG.error = 1;
        swWarn("alloc_cidmap failed");
        return CORO_LIMIT;
    }
    COROG.error = 0;
    ++COROG.coro_num;
    args.cid = cid;
    stCoRoutine_t* _co = NULL;
    stCoRoutineAttr_t attr;
    attr.stack_size = 1024 * 1024 * 8;
    co_create(&_co, &attr, func, &args);
    coroutine_t* coro = new coroutine_t;
    coro->rep = _co;
    g_coroutine_pool[cid] = coro;
    coroutine_resume(coro);
    return cid;
}

void coroutine_yield(coroutine_t *co)
{
    stCoRoutine_t *_co = co->rep;
    co_yield(_co);
}

coro_task *get_current_task()
{
    return COROG.call_stack[COROG.call_stack_size - 1];
}

int coroutine_get_cid()
{
    if (unlikely(COROG.active == 0))
    {
        return -1;
    }
    else
    {
        coro_task *task = get_current_task();
        stCoRoutine_t *co = GetCurrThreadCo();
        if (!task || (co && co->cIsMain))
        {
            return -1;
        }
        else
        {
            return task->cid;
        }
    }
}

/* allocate cid for coroutine */
typedef struct cidmap
{
    uint32_t nr_free;
    char page[65536];
} cidmap_t;

/* 1 <= cid <= 524288 */
static cidmap_t cidmap =
{ MAX_CORO_NUM_LIMIT,
{ 0 } };

int last_cid = -1;

inline int test_and_set_bit(int cid, void *addr)
{
    uint32_t mask = 1U << (cid & 0x1f);
    uint32_t *p = ((uint32_t*) addr) + (cid >> 5);
    uint32_t old = *p;

    *p = old | mask;

    return (old & mask) == 0;
}

inline void clear_bit(int cid, void *addr)
{
    uint32_t mask = 1U << (cid & 0x1f);
    uint32_t *p = ((uint32_t*) addr) + (cid >> 5);
    uint32_t old = *p;

    *p = old & ~mask;
}

/* find next free cid */
int find_next_zero_bit(void *addr, int cid)
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
        cid &= 0x7fff;
    }

    return cid;
}

int alloc_cidmap()
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

void free_cidmap(int cid)
{
    cid--;
    cidmap.nr_free++;
    clear_bit(cid, &cidmap.page);
}

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif
#endif
