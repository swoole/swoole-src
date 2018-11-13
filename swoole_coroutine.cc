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

static sw_inline void php_coro_save_current_stack_to(coro_task *task)
{
    task->execute_data = EG(current_execute_data);
    task->vm_stack = EG(vm_stack);
    task->vm_stack_top = EG(vm_stack_top);
    task->vm_stack_top = EG(vm_stack_end);
    SW_SAVE_EG_SCOPE(task->scope);
}

static sw_inline coro_task* php_coro_get_current_task()
{
    coro_task *task = (coro_task *) coroutine_get_current_task();
    if (!task)
    {
        task = &COROG.task;
    }
    php_coro_save_current_stack_to(task);
    return task;
}

static sw_inline void php_coro_set_current_stack_to(coro_task *task)
{
    EG(current_execute_data) = task->execute_data;
    EG(vm_stack) = task->vm_stack;
    EG(vm_stack_top) = task->vm_stack_top;
    EG(vm_stack_end) = task->vm_stack_end;
    SW_SET_EG_SCOPE(task->scope);
}

static sw_inline void php_coro_task_init(int cid, coro_task *task, zend_execute_data *call, coro_task *origin_task)
{
#ifdef SW_LOG_TRACE_OPEN
    task->cid = cid;
#endif
    task->execute_data = call;
    task->vm_stack = EG(vm_stack);
    task->vm_stack_top = EG(vm_stack_top);
    task->vm_stack_end = EG(vm_stack_end);
    task->origin_task = origin_task;
    task->output_ptr = nullptr;
    if (cid > 0)
    {
        task->co = coroutine_get_by_id(cid);
        coroutine_set_task(task->co, (void *) task);
    }
    else
    {
        // COROG.task have no C stack coroutine
        task->co = nullptr;
    }
}

/**
 * The meaning of the task argument in coro switch functions
 *
 * create: origin_task
 * yield: current_task
 * resume: target_task
 * close: current_task
 *
 */

static sw_inline void php_coro_og_save_current_to(coro_task *task)
{
    task->output_ptr = (zend_output_globals *) emalloc(sizeof(zend_output_globals));
    memcpy(task->output_ptr, SWOG, sizeof(zend_output_globals));
    php_output_activate();
}

static sw_inline void php_coro_og_current_set_to(coro_task *task)
{
    memcpy(SWOG, task->output_ptr, sizeof(zend_output_globals));
    efree(task->output_ptr);
    task->output_ptr = NULL;
}

static sw_inline void php_coro_og_create(coro_task *task)
{
    if (OG(handlers).elements)
    {
        php_coro_og_save_current_to(task);
    }
    else
    {
        task->output_ptr = NULL;
    }
}

static sw_inline void php_coro_og_yield(coro_task *task)
{
    if (OG(handlers).elements)
    {
        php_coro_og_save_current_to(task);
    }
    else
    {
        task->output_ptr = NULL;
    }
    if (task->origin_task->output_ptr)
    {
        php_coro_og_current_set_to(task->origin_task);
    }
}

static sw_inline void php_coro_og_resume(coro_task *task)
{
    if (OG(handlers).elements)
    {
        php_coro_og_save_current_to(task->origin_task);
    }
    else
    {
        task->origin_task->output_ptr = NULL;
    }
    if (task->output_ptr)
    {
        php_coro_og_current_set_to(task);
    }
}

static sw_inline void php_coro_og_close(coro_task *task)
{
    if (OG(handlers).elements)
    {
        if (OG(active))
        {
            php_output_end_all();
        }
        php_output_deactivate();
        php_output_activate();
    }
    if (task->output_ptr)
    {
        efree(task->output_ptr);
        task->output_ptr = nullptr;
    }
}

void coro_init(void)
{
    if (zend_get_module_started("xdebug") == SUCCESS)
    {
        swWarn("xdebug do not support coroutine, please notice that it lead to coredump.");
    }
    //save init vm
    php_coro_task_init(0, &COROG.task, EG(current_execute_data), nullptr);

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
}

static void php_coro_create(void *arg)
{
    php_args *php_arg = (php_args *) arg;
    zend_fcall_info_cache *fci_cache = php_arg->fci_cache;
    zval **argv = php_arg->argv;
    int argc = php_arg->argc;
    zval *retval = php_arg->retval;
    coro_task *origin_task = php_arg->origin_task;

    int cid = coroutine_get_current_cid();
    int i;
    zend_function *func;
    coro_task *task;

    func = fci_cache->function_handler;
    sw_vm_stack_init();
    zend_execute_data *call = (zend_execute_data *) (EG(vm_stack_top));

    task = (coro_task *) EG(vm_stack_top);
    EG(vm_stack_top) = (zval *) ((char *) call + TASK_SLOT * sizeof(zval));

    call = zend_vm_stack_push_call_frame(
        ZEND_CALL_TOP_FUNCTION | ZEND_CALL_ALLOCATED,
        func, argc,
        fci_cache->called_scope, fci_cache->object
    );

    SW_SET_EG_SCOPE(func->common.scope);
    SW_SAVE_EG_SCOPE(task->scope);

    for (i = 0; i < argc; ++i)
    {
        zval *target;
        target = ZEND_CALL_ARG(call, i + 1);
        ZVAL_COPY(target, argv[i]);
    }
    call->symbol_table = NULL;

    // EG(current_execute_data) = NULL; // for backtrace
    if (UNEXPECTED(func->op_array.fn_flags & ZEND_ACC_CLOSURE))
    {
        uint32_t call_info;
        GC_ADDREF(ZEND_CLOSURE_OBJECT(func));
        call_info = ZEND_CALL_CLOSURE;
        ZEND_ADD_CALL_FLAG(call, call_info);
    }
    zend_init_execute_data(call, &func->op_array, retval);

    php_coro_task_init(cid, task, call, origin_task);

    if (SwooleG.hooks[SW_GLOBAL_HOOK_ON_CORO_START])
    {
        swoole_call_hook(SW_GLOBAL_HOOK_ON_CORO_START, task);
    }
    swTraceLog(SW_TRACE_COROUTINE, "Create coro id: %d, origin cid: %d, coro total count: %d, heap size: %zu", cid, task->origin_task->cid, COROG.coro_num, zend_memory_usage(0));

    php_coro_og_create(origin_task);
    EG(current_execute_data) = task->execute_data;
    zend_execute_ex(EG(current_execute_data));

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
}

static sw_inline void php_coro_yield(coro_task *task)
{
    swTraceLog(SW_TRACE_COROUTINE,"php_coro_yield cid=%d", task->cid);
    php_coro_save_current_stack_to(task);
    php_coro_set_current_stack_to(task->origin_task);
    php_coro_og_yield(task);
}

static sw_inline void php_coro_resume(coro_task *task)
{
    swTraceLog(SW_TRACE_COROUTINE,"php_coro_resume cid=%d", task->cid);
    task->origin_task = php_coro_get_current_task();
    php_coro_set_current_stack_to(task);
    php_coro_og_resume(task);
}

static sw_inline void php_coro_close(coro_task *task)
{
    php_coro_og_close(task);
    php_coro_yield(task);
}

void internal_coro_resume(void *arg)
{
    coro_task *task = (coro_task *) arg;
    php_coro_resume(task);
}

void internal_coro_yield(void *arg)
{
    coro_task *task = (coro_task *) arg;
    php_coro_yield(task);
}

void coro_check(void)
{
    if (unlikely(!sw_coro_is_in()))
    {
        swoole_php_fatal_error(E_ERROR, "must be called in the coroutine.");
    }
}

void coro_destroy(void)
{
}

void sw_coro_check_bind(const char *name, int bind_cid)
{
    if (unlikely(bind_cid > 0))
    {
        swString *buffer = SwooleTG.buffer_stack;
        sw_get_debug_print_backtrace(buffer, DEBUG_BACKTRACE_IGNORE_ARGS, 3);
        swoole_error_log(
            SW_LOG_ERROR, SW_ERROR_CO_HAS_BEEN_BOUND,
            "%s has already been bound to another coroutine #%d, "
            "reading or writing of the same socket in multiple coroutines at the same time is not allowed.\n"
            "%.*s", name, bind_cid, (int) buffer->length, buffer->str
        );
        exit(255);
    }
}

int sw_coro_create(zend_fcall_info_cache *fci_cache, zval **argv, int argc, zval *retval, void *post_callback,
        void *params)
{
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
    php_args.origin_task = php_coro_get_current_task();

    COROG.error = 0;
    COROG.coro_num++;

    if (COROG.coro_num > COROG.peak_coro_num)
    {
        COROG.peak_coro_num = COROG.coro_num;
    }

    return coroutine_create(php_coro_create, (void*) &php_args);
}

void sw_coro_save(zval *return_value, php_context *sw_current_context)
{
    SWCC(current_coro_return_value_ptr) = return_value;
    SWCC(current_execute_data) = EG(current_execute_data);
    SWCC(current_vm_stack) = EG(vm_stack);
    SWCC(current_vm_stack_top) = EG(vm_stack_top);
    SWCC(current_vm_stack_end) = EG(vm_stack_end);
    SWCC(current_task) = (coro_task *) coroutine_get_current_task();
}

void sw_coro_yield()
{
    if (unlikely(!sw_coro_is_in()))
    {
        swoole_php_fatal_error(E_ERROR, "must be called in the coroutine.");
    }
    coro_task *task = (coro_task *) coroutine_get_current_task();
    php_coro_yield(task);
    coroutine_yield_naked(task->co);
}

int sw_coro_resume(php_context *sw_current_context, zval *retval, zval *coro_retval)
{
    coro_task *task = SWCC(current_task);
    php_coro_resume(task);
    if (EG(current_execute_data)->prev_execute_data->opline->result_type != IS_UNUSED && retval)
    {
        ZVAL_COPY(SWCC(current_coro_return_value_ptr), retval);
    }

    coroutine_resume_naked(task->co);

    if (unlikely(EG(exception)))
    {
        if (retval)
        {
            zval_ptr_dtor(retval);
        }
        zend_exception_error(EG(exception), E_ERROR);
    }
    return CORO_END;
}

void sw_coro_close()
{
    coro_task *task = (coro_task *) coroutine_get_current_task();

    if (SwooleG.hooks[SW_GLOBAL_HOOK_ON_CORO_STOP])
    {
        swoole_call_hook(SW_GLOBAL_HOOK_ON_CORO_STOP, task);
    }

    php_coro_close(task);
    efree(task->vm_stack);
    COROG.coro_num--;

    swTraceLog(SW_TRACE_COROUTINE, "coro close cid=%d and %d remained. usage size: %zu. malloc size: %zu", task->cid, COROG.coro_num, zend_memory_usage(0), zend_memory_usage(1));
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
