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

typedef void (*coro_php_create_t)();
typedef void (*coro_php_yield_t)(void*);
typedef void (*coro_php_resume_t)(void*);
typedef void (*coro_php_close_t)();

typedef enum
{
    SW_CORO_YIELD = 0, SW_CORO_SUSPENDED, SW_CORO_RUNNING, SW_CORO_END,
} sw_coro_state;

/* basic api */
int coroutine_create(coroutine_func_t func, void* args);
void coroutine_resume(coroutine_t *co);
void coroutine_yield(coroutine_t *co);
void coroutine_resume_naked(coroutine_t *co);
void coroutine_yield_naked(coroutine_t *co);
void coroutine_release(coroutine_t *co);
/* co task */
void coroutine_set_task(coroutine_t *co, void *ptr);
void* coroutine_get_current_task();
void* coroutine_get_task_by_cid(int cid);
/* get coroutine */
coroutine_t* coroutine_get_current();
coroutine_t *coroutine_get_by_id(int cid);
/* get cid */
int coroutine_get_cid(coroutine_t *co);
int coroutine_get_current_cid();
/* cid api */
int coroutine_test_alloc_cid();
void coroutine_test_free_cid(int cid);
void coroutine_set_stack_size(int stack_size);
/* callback */
void coroutine_set_onYield(coro_php_yield_t func);
void coroutine_set_onResume(coro_php_resume_t func);
void coroutine_set_onClose(coro_php_close_t func);

void internal_coro_yield(void *return_value);
void internal_coro_resume(void *data);

#ifdef __cplusplus
}  /* end extern "C" */
#endif
#endif
