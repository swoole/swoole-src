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
    Context *ctx;
    int cid;
};

static struct
{
    int stack_size;
    int current_cid;
    struct coroutine_s *coroutines[MAX_CORO_NUM_LIMIT + 1];
    coroutine_close_t onClose;
} swCoroG =
{ SW_DEFAULT_C_STACK_SIZE, -1,
{ NULL, }, NULL };

/* 1 <= cid <= 524288 */
static cidmap_t cidmap =
{ MAX_CORO_NUM_LIMIT,
{ 0 } };

int last_cid = -1;

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
        cid &= 0x7fff;
    }

    return cid;
}

static int alloc_cidmap()
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
