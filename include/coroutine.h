#ifndef SW_COROUTINE_H_
#define SW_COROUTINE_H_
#include "php_swoole.h"
#ifdef __cplusplus
extern "C" {
#endif

void coro_yield();
void coro_handle_timeout();

#define DEFAULT_MAX_CORO_NUM 3000
#define DEFAULT_STACK_SIZE   8192
#define MAX_CORO_NUM_LIMIT   0x80000

typedef struct coroutine_t                 coroutine_t;

typedef enum
{
    SW_CORO_YIELD = 0, SW_CORO_SUSPENDED, SW_CORO_RUNNING, SW_CORO_END,
} sw_coro_state;

typedef struct _php_args
{
    zend_fcall_info_cache *fci_cache;
    zval **argv;
    int argc;
    zval *retval;
    void *post_callback;
    void *params;
    int cid;
} php_args;

typedef struct _coro_task
{
    int cid;
    sw_coro_state state;
    coroutine_t *co;
    zend_execute_data *execute_data;
    zend_vm_stack stack;
    zval *vm_stack_top;
    zval *vm_stack_end;

    zend_vm_stack origin_stack;
    zval *origin_vm_stack_top;
    zval *origin_vm_stack_end;

    zend_execute_data *yield_execute_data;
    zend_vm_stack yield_stack;
    zval *yield_vm_stack_top;
    zval *yield_vm_stack_end;
    zend_bool is_yield;
    /**
     * user coroutine
     */
    zval *function;
    time_t start_time;
    void (*post_callback)(void *param);
    void *post_callback_params;
    php_args args;
} coro_task;

typedef void *(*php_func_co_t)( void * );
int coroutine_create(php_func_co_t func,php_args args);
void coroutine_resume(coroutine_t *co);
void coroutine_yield(coroutine_t *co);
void coroutine_release(coroutine_t *co);
void coroutine_set_task(int cid, coro_task *task);
coroutine_t *get_coroutine_by_id(int cid);
coro_task *get_current_task();


int alloc_cidmap();
void free_cidmap(int cid);

#ifdef __cplusplus
}  /* end extern "C" */
#endif

#endif
