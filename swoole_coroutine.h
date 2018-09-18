#ifndef SWOOLE_CORO_INCLUDE_C_H_
#define SWOOLE_CORO_INCLUDE_C_H_

#ifdef __cplusplus
extern "C" {
#endif
#include "coroutine.h"
#include "zend_vm.h"
#include "zend_closures.h"

/* PHP 7.3 compatibility macro {{{*/
#ifndef ZEND_CLOSURE_OBJECT
# define ZEND_CLOSURE_OBJECT(func) (zend_object*)func->op_array.prototype
#endif
#ifndef GC_ADDREF
# define GC_ADDREF(ref) ++GC_REFCOUNT(ref)
# define GC_DELREF(ref) --GC_REFCOUNT(ref)
#endif/*}}}*/

#define SW_EX_CV_NUM(ex, n) (((zval ***)(((char *)(ex)) + ZEND_MM_ALIGNED_SIZE(sizeof(zend_execute_data)))) + n)
#define SW_EX_CV(var) (*SW_EX_CV_NUM(execute_data, var))

typedef enum
{
    SW_CORO_CONTEXT_RUNNING, SW_CORO_CONTEXT_IN_DELAYED_TIMEOUT_LIST, SW_CORO_CONTEXT_TERM
} php_context_state;

typedef struct _php_args
{
    zend_fcall_info_cache *fci_cache;
    zval **argv;
    int argc;
    zval *retval;
    void *post_callback;
    void *params;
} php_args;

typedef struct _coro_task
{
    int cid;
    sw_coro_state state;
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

    zend_output_globals *current_coro_output_ptr;
    /**
     * user coroutine
     */
    coroutine_t *co;
    zval *function;
    time_t start_time;
    void (*post_callback)(void *param);
    void *post_callback_params;
    php_args args;
} coro_task;

typedef struct _php_context
{
    zval **current_coro_return_value_ptr_ptr;
    zval *current_coro_return_value_ptr;
    zval coro_params;
    void *private_data;
    swTimer_node *timer;
    zval **current_eg_return_value_ptr_ptr;
    zend_execute_data *current_execute_data;
    zval *current_vm_stack_top;
    zval *current_vm_stack_end;
    zval *allocated_return_value_ptr;
    coro_task *current_task;
    zend_vm_stack current_vm_stack;
    php_context_state state;
    zend_output_globals *current_coro_output_ptr;
} php_context;

typedef struct _coro_global
{
    uint32_t coro_num;
    uint32_t max_coro_num;
    uint32_t peak_coro_num;
    uint32_t stack_size;
    zend_vm_stack origin_vm_stack;
    zval *origin_vm_stack_top;
    zval *origin_vm_stack_end;
    zval *allocated_return_value_ptr;
    zend_execute_data *origin_ex;
    coro_task *current_coro;
    zend_bool active;
    int error;
} coro_global;

typedef struct _swTimer_coro_callback
{
    int ms;
    int cli_fd;
    long *timeout_id;
    void* data;
} swTimer_coro_callback;

extern coro_global COROG;

int sw_get_current_cid();
int coro_init(TSRMLS_D);
void coro_destroy(TSRMLS_D);
void coro_check(TSRMLS_D);

#define coro_create(op_array, argv, argc, retval, post_callback, param) \
        sw_coro_create(op_array, argv, argc, *retval, post_callback, param)
#define coro_save(sw_php_context) \
        sw_coro_save(return_value, sw_php_context);
#define coro_resume(sw_current_context, retval, coro_retval) \
        sw_coro_resume(sw_current_context, retval, *coro_retval)
#define coro_yield() sw_coro_yield()

#define coro_use_return_value(); *(zend_uchar *) &execute_data->prev_execute_data->opline->result_type = IS_VAR;

/* output globals */
#define SWOG ((zend_output_globals *) &OG(handlers))

int sw_coro_create(zend_fcall_info_cache *op_array, zval **argv, int argc, zval *retval, void *post_callback, void *param);
void sw_coro_yield();
void sw_coro_close();
int sw_coro_resume(php_context *sw_current_context, zval *retval, zval *coro_retval);
void sw_coro_save(zval *return_value, php_context *sw_php_context);
void sw_coro_set_stack_size(int stack_size);

extern int swoole_coroutine_sleep(double msec);
int php_swoole_add_timer_coro(int ms, int cli_fd, long *timeout_id, void* param, swLinkedList_node **node TSRMLS_DC);
int php_swoole_clear_timer_coro(long id TSRMLS_DC);

#ifdef __cplusplus
}  /* end extern "C" */
#endif
#endif  /* SWOOLE_CORO_INCLUDE_C_H_ */
