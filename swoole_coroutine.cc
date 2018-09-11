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
  | Author: Xinyu Zhu  <xyzhu1120@gmail.com>                             |
  |         shiguangqi <shiguangqi2008@gmail.com>                        |
  +----------------------------------------------------------------------+
 */

#include "php_swoole.h"

#ifdef SW_COROUTINE
#include "swoole_coroutine.h"

#define TASK_SLOT \
    ((int)((ZEND_MM_ALIGNED_SIZE(sizeof(coro_task)) + ZEND_MM_ALIGNED_SIZE(sizeof(zval)) - 1) / ZEND_MM_ALIGNED_SIZE(sizeof(zval))))
#define SWCC(x) sw_current_context->x

coro_global COROG;
static void sw_coro_func(void *);
static zend_bool is_xdebug_started = 0;

#if PHP_VERSION_ID >= 70200
static inline void sw_vm_stack_init(void)
{
    uint32_t size = COROG.stack_size;
    zend_vm_stack page = (zend_vm_stack) emalloc(size);

    page->top = ZEND_VM_STACK_ELEMENTS(page);
    page->end = (zval*) ((char*) page + size);
    page->prev = NULL;

    EG(vm_stack) = page;
    EG(vm_stack)->top++;
    EG(vm_stack_top) = EG(vm_stack)->top;
    EG(vm_stack_end) = EG(vm_stack)->end;
}
#else
#define sw_vm_stack_init zend_vm_stack_init
#endif

int coro_init(TSRMLS_D)
{
    if (zend_get_module_started("xdebug") == SUCCESS)
    {
        is_xdebug_started = 1;
    }
    //save init vm
    COROG.origin_vm_stack = EG(vm_stack);
    COROG.origin_vm_stack_top = EG(vm_stack_top);
    COROG.origin_vm_stack_end = EG(vm_stack_end);

    COROG.coro_num = 0;
    COROG.peak_coro_num = 0;
    if (COROG.max_coro_num <= 0)
    {
        COROG.max_coro_num = DEFAULT_MAX_CORO_NUM;
    }
    if (COROG.stack_size <= 0)
    {
        COROG.stack_size = DEFAULT_STACK_SIZE;
    }

    COROG.active = 1;
    /* set functions */
    coroutine_set_onYield(internal_coro_yield);
    coroutine_set_onResume(internal_coro_resume);
    coroutine_set_onClose(sw_coro_close);
    return 0;
}

static void resume_php_stack(coro_task *task)
{
    COROG.current_coro = task;
    swTraceLog(SW_TRACE_COROUTINE,"sw_coro_resume coro id %d", COROG.current_coro->cid);
    task->state = SW_CORO_RUNNING;
    EG(current_execute_data) = task->yield_execute_data;
    EG(vm_stack) = task->yield_stack;
    EG(vm_stack_top) = task->yield_vm_stack_top;
    EG(vm_stack_end) = task->yield_vm_stack_end;
}

static void save_php_stack(coro_task *task)
{
    swTraceLog(SW_TRACE_COROUTINE,"coro_yield coro id %d", task->cid);
    task->state = SW_CORO_YIELD;
    task->is_yield = 1;
    /* save vm stack */
    task->yield_execute_data = EG(current_execute_data);
    task->yield_stack = EG(vm_stack);
    task->yield_vm_stack_top = EG(vm_stack_top);
    task->yield_vm_stack_end = EG(vm_stack_end);
    /* restore vm stack */
    EG(vm_stack) = task->origin_stack;
    EG(vm_stack_top) = task->origin_vm_stack_top;
    EG(vm_stack_end) = task->origin_vm_stack_end;
#if PHP_VERSION_ID < 70100
    EG(scope) = task->execute_data->func->common.scope;
#endif
}
void internal_coro_resume(void *arg)
{
    coro_task *task = (coro_task *)arg;
    resume_php_stack(task);

    if (OG(handlers).elements)
    {
        php_output_deactivate();
        if (!task->current_coro_output_ptr)
        {
            php_output_activate();
        }
    }
    /* resume output control global */
    if (task->current_coro_output_ptr)
    {
        memcpy(SWOG, task->current_coro_output_ptr, sizeof(zend_output_globals));
        efree(task->current_coro_output_ptr);
        task->current_coro_output_ptr = NULL;
    }
    swTraceLog(SW_TRACE_COROUTINE, "cid=%d", task->cid);
}

void internal_coro_yield(void *arg)
{
    coro_task *task = (coro_task *)arg;
    save_php_stack(task);
    /* save output control global */
    if (OG(active))
    {
        zend_output_globals *coro_output_globals_ptr = (zend_output_globals *) emalloc(sizeof(zend_output_globals));
        memcpy(coro_output_globals_ptr, SWOG, sizeof(zend_output_globals));
        task->current_coro_output_ptr = coro_output_globals_ptr;
        php_output_activate();
    }
    else
    {
        task->current_coro_output_ptr = NULL;
    }
}

void coro_check(TSRMLS_D)
{
    if (sw_get_current_cid() == -1)
    {
        swoole_php_fatal_error(E_ERROR, "must be called in the coroutine.");
    }
}

void coro_destroy(TSRMLS_D)
{

}

static void sw_coro_func(void *arg)
{
    php_args *php_arg = (php_args *) arg;
    zend_fcall_info_cache *fci_cache = php_arg->fci_cache;
    zval **argv = php_arg->argv;
    int argc = php_arg->argc;
    zval *retval = php_arg->retval;
    int cid = coroutine_get_current_cid();

    int i;
    zend_function *func;
    coro_task *task;

    zend_vm_stack origin_vm_stack = EG(vm_stack);
    zval *origin_vm_stack_top = EG(vm_stack_top);
    zval *origin_vm_stack_end = EG(vm_stack_end);

    func = fci_cache->function_handler;
    sw_vm_stack_init();
    zend_execute_data *call = (zend_execute_data *) (EG(vm_stack_top));

    task = (coro_task *) EG(vm_stack_top);
    EG(vm_stack_top) = (zval *) ((char *) call + TASK_SLOT * sizeof(zval));

    call = zend_vm_stack_push_call_frame(ZEND_CALL_TOP_FUNCTION | ZEND_CALL_ALLOCATED, func, argc,
            fci_cache->called_scope, fci_cache->object);

#if PHP_VERSION_ID < 70100
    EG(scope) = func->common.scope;
#endif

    for (i = 0; i < argc; ++i)
    {
        zval *target;
        target = ZEND_CALL_ARG(call, i + 1);
        ZVAL_COPY(target, argv[i]);
    }
    call->symbol_table = NULL;

    EG(current_execute_data) = NULL;
    if (UNEXPECTED(func->op_array.fn_flags & ZEND_ACC_CLOSURE))
    {
        uint32_t call_info;
        GC_ADDREF(ZEND_CLOSURE_OBJECT(func));
        call_info = ZEND_CALL_CLOSURE;
        ZEND_ADD_CALL_FLAG(call, call_info);
    }
    zend_init_execute_data(call, &func->op_array, retval);

    task->cid = cid;
    task->execute_data = call;
    task->stack = EG(vm_stack);
    task->vm_stack_top = EG(vm_stack_top);
    task->vm_stack_end = EG(vm_stack_end);
    task->origin_stack = origin_vm_stack;
    task->origin_vm_stack_top = origin_vm_stack_top;
    task->origin_vm_stack_end = origin_vm_stack_end;
    task->start_time = time(NULL);
    task->function = NULL;
    task->is_yield = 0;
    task->state = SW_CORO_RUNNING;
    task->co = coroutine_get_by_id(cid);
    coroutine_set_task(task->co, (void *)task);

    if (SwooleG.hooks[SW_GLOBAL_HOOK_ON_CORO_START])
    {
        swoole_call_hook(SW_GLOBAL_HOOK_ON_CORO_START, task);
    }
    COROG.current_coro = task;
    swTraceLog(SW_TRACE_COROUTINE, "Create coro id: %d, coro total count: %d, heap size: %zu", cid, COROG.coro_num, zend_memory_usage(0));

    EG(current_execute_data) = task->execute_data;
    EG(vm_stack) = task->stack;
    EG(vm_stack_top) = task->vm_stack_top;
    EG(vm_stack_end) = task->vm_stack_end;
    zend_execute_ex(EG(current_execute_data) TSRMLS_CC);
}

int sw_coro_create(zend_fcall_info_cache *fci_cache, zval **argv, int argc, zval *retval, void *post_callback,
        void *params)
{
    if (unlikely(is_xdebug_started == 1))
    {
        swWarn("xdebug do not support coroutine, please notice that it lead to coredump.");
    }

    if (unlikely(COROG.coro_num >= COROG.max_coro_num) )
    {
        COROG.error = 1;
        swWarn("exceed max number of coro_num %d, max_coro_num:%d", COROG.coro_num, COROG.max_coro_num);
        return CORO_LIMIT;
    }

    php_args php_args;
    php_args.fci_cache = fci_cache;
    php_args.argv = argv;
    php_args.argc = argc;
    php_args.retval = retval;
    php_args.post_callback = post_callback;
    php_args.params = params;

    COROG.error = 0;
    COROG.coro_num++;

    if (COROG.coro_num > COROG.peak_coro_num)
    {
        COROG.peak_coro_num = COROG.coro_num;
    }

    /**===================Before Coroutine======================**/
    zend_output_globals *coro_output_globals_ptr = NULL;
    if (OG(active)) // save the current OG
    {
        coro_output_globals_ptr = (zend_output_globals *) emalloc(sizeof(zend_output_globals));
        memcpy(coro_output_globals_ptr, SWOG, sizeof(zend_output_globals));
        php_output_activate();
    }
    /**=========================================================**/

    int ret = coroutine_create(sw_coro_func, (void*) &php_args);

    /**===================After Coroutine=======================**/
    if (coro_output_globals_ptr) // resume the parent OG
    {
        memcpy(SWOG, coro_output_globals_ptr, sizeof(zend_output_globals));
        efree(coro_output_globals_ptr);
    }
    /**========================================================**/
    return ret;
}

void sw_coro_save(zval *return_value, php_context *sw_current_context)
{
    SWCC(current_coro_return_value_ptr) = return_value;
    SWCC(current_execute_data) = EG(current_execute_data);
    SWCC(current_vm_stack) = EG(vm_stack);
    SWCC(current_vm_stack_top) = EG(vm_stack_top);
    SWCC(current_vm_stack_end) = EG(vm_stack_end);
    SWCC(current_task) = (coro_task *) coroutine_get_current_task();

    if (OG(active))
    {
        zend_output_globals *coro_output_globals_ptr = (zend_output_globals *) emalloc(sizeof(zend_output_globals));
        memcpy(coro_output_globals_ptr, SWOG, sizeof(zend_output_globals));
        SWCC(current_coro_output_ptr) = coro_output_globals_ptr;
        php_output_activate();
    }
    else
    {
        SWCC(current_coro_output_ptr) = NULL;
    }
}

int sw_coro_resume(php_context *sw_current_context, zval *retval, zval *coro_retval)
{
    coro_task *task = SWCC(current_task);
    resume_php_stack(task);
    if (EG(current_execute_data)->prev_execute_data->opline->result_type != IS_UNUSED && retval)
    {
        ZVAL_COPY(SWCC(current_coro_return_value_ptr), retval);
    }

    if (OG(handlers).elements)
    {
        php_output_deactivate();
        if (!SWCC(current_coro_output_ptr))
        {
            php_output_activate();
        }
    }

    if (SWCC(current_coro_output_ptr))
    {
        memcpy(SWOG, SWCC(current_coro_output_ptr), sizeof(zend_output_globals));
        efree(SWCC(current_coro_output_ptr));
        SWCC(current_coro_output_ptr) = NULL;
    }

    swTraceLog(SW_TRACE_COROUTINE, "cid=%d", task->cid);
    coroutine_resume_naked(task->co);

    if (unlikely(EG(exception)))
    {
        if (retval)
        {
            zval_ptr_dtor(retval);
        }
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    return CORO_END;
}

void sw_coro_yield()
{
    if (unlikely(sw_get_current_cid() == -1))
    {
        swoole_php_fatal_error(E_ERROR, "must be called in the coroutine.");
    }
    coro_task *task = (coro_task *) coroutine_get_current_task();
    save_php_stack(task);
    coroutine_yield_naked(task->co);
}

void sw_coro_close()
{
    coro_task *task = (coro_task *) coroutine_get_current_task();
    swTraceLog(SW_TRACE_COROUTINE,"coro_close coro id %d", task->cid);

    if (SwooleG.hooks[SW_GLOBAL_HOOK_ON_CORO_STOP])
    {
        swoole_call_hook(SW_GLOBAL_HOOK_ON_CORO_STOP, task);
    }

    if (!task->is_yield)
    {
        EG(vm_stack) = task->origin_stack;
        EG(vm_stack_top) = task->origin_vm_stack_top;
        EG(vm_stack_end) = task->origin_vm_stack_end;
    }
    else
    {
        EG(vm_stack) = COROG.origin_vm_stack;
        EG(vm_stack_top) = COROG.origin_vm_stack_top;
        EG(vm_stack_end) = COROG.origin_vm_stack_end;
    }
    efree(task->stack);
    COROG.coro_num--;
    COROG.current_coro = NULL;

    if (OG(active))
    {
        php_output_end_all();
    }
    if (OG(handlers).elements)
    {
        php_output_deactivate();
        php_output_activate();
    }
    swTraceLog(SW_TRACE_COROUTINE, "close coro and %d remained. usage size: %zu. malloc size: %zu", COROG.coro_num, zend_memory_usage(0), zend_memory_usage(1));
}

int sw_get_current_cid()
{
    if (unlikely(COROG.active == 0))
    {
        return -1;
    }
    else
    {
        return coroutine_get_current_cid();
    }
}

void sw_coro_set_stack_size(int stack_size)
{
    coroutine_set_stack_size(stack_size);
}

#endif
