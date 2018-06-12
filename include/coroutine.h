#ifndef SW_COROUTINE_H_
#define SW_COROUTINE_H_

#include "swoole.h"
#ifdef __cplusplus
extern "C"
{
#endif

void coro_yield();
void coro_handle_timeout();

#define DEFAULT_MAX_CORO_NUM 3000
#define DEFAULT_STACK_SIZE   8192
#define MAX_CORO_NUM_LIMIT   0x80000

#define CORO_END 0
#define CORO_YIELD 1
#define CORO_LIMIT -1
#define CORO_SAVE 3

typedef struct coroutine_s coroutine_t;
typedef void (*coroutine_func_t)(void*);
typedef void (*coroutine_close_t)();

typedef enum
{
    SW_CORO_YIELD = 0, SW_CORO_SUSPENDED, SW_CORO_RUNNING, SW_CORO_END,
} sw_coro_state;

int coroutine_create(coroutine_func_t func, void* args);
void coroutine_resume(coroutine_t *co);
void coroutine_yield(coroutine_t *co);
void coroutine_release(coroutine_t *co);
coroutine_t *coroutine_get_by_id(int cid);
int coroutine_get_cid();
void coroutine_set_close(coroutine_close_t func);

#ifdef __cplusplus
}  /* end extern "C" */
#endif
#endif
