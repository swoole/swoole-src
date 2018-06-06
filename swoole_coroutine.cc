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
#include "coroutine.h"
#include "swoole_coroutine.h"
#include "thirdparty/libco/co_routine.h"
#include "thirdparty/libco/co_routine_inner.h"
#include "zend_vm.h"

/* PHP 7.3 compatibility macro {{{*/
#ifndef ZEND_CLOSURE_OBJECT
# define ZEND_CLOSURE_OBJECT(func) (zend_object*)func->op_array.prototype
#endif
#ifndef GC_ADDREF
# define GC_ADDREF(ref) ++GC_REFCOUNT(ref)
# define GC_DELREF(ref) --GC_REFCOUNT(ref)
#endif/*}}}*/

#define TASK_SLOT \
    ((int)((ZEND_MM_ALIGNED_SIZE(sizeof(coro_task)) + ZEND_MM_ALIGNED_SIZE(sizeof(zval)) - 1) / ZEND_MM_ALIGNED_SIZE(sizeof(zval))))
#define SWCC(x) sw_current_context->x
coro_global COROG;

static int sw_terminate_opcode_handler(zend_execute_data *execute_data);
static int sw_return_opcode_handler(zend_execute_data *execute_data);
static coro_task* sw_get_current_task();

static zend_op_array sw_terminate_func;
static zend_try_catch_element sw_terminate_try_catch_array =
{ 0, 1, 0, 0 };
static zend_op sw_terminate_op[2];
static zend_op_array sw_return_func;
static zend_op sw_return_op[1];
zend_execute_data return_frame;

#if PHP_MAJOR_VERSION >= 7 && PHP_MINOR_VERSION >= 2
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
        swoole_php_fatal_error(E_ERROR, "can not use xdebug in swoole coroutine, please remove xdebug in php.ini and retry.");
        return 0;
    }

    zend_uchar opcode = ZEND_VM_LAST_OPCODE + 1;
    while (1)
    {
        if (opcode == 255)
        {
            swoole_php_fatal_error(E_ERROR, "all of opcode was defined, please check php.ini extensions.");
            return FAILURE;
        }
        else if (zend_get_user_opcode_handler(opcode) == NULL)
        {
            break;
        }
        opcode++;
    }
    zend_set_user_opcode_handler(opcode, sw_terminate_opcode_handler);

    memset(sw_terminate_op, 0, sizeof(sw_terminate_op));
    sw_terminate_op[0].opcode = opcode;
    zend_vm_set_opcode_handler_ex(sw_terminate_op, 0, 0, 0);
    sw_terminate_op[1].opcode = opcode;
    zend_vm_set_opcode_handler_ex(sw_terminate_op + 1, 0, 0, 0);

    memset(&sw_terminate_func, 0, sizeof(sw_terminate_func));
    sw_terminate_func.type = ZEND_USER_FUNCTION;
    sw_terminate_func.function_name = zend_string_init("close_coro", sizeof("close_coro") - 1, 1);
    sw_terminate_func.filename = ZSTR_EMPTY_ALLOC();
    sw_terminate_func.opcodes = sw_terminate_op;
    sw_terminate_func.last_try_catch = 1;
    sw_terminate_func.try_catch_array = &sw_terminate_try_catch_array;

    while (1)
    {
        if (opcode == 255)
        {
            swoole_php_fatal_error(E_ERROR, "all of opcode was defined, please check php.ini extensions.");
            return FAILURE;
        }
        else if (zend_get_user_opcode_handler(opcode) == NULL)
        {
            break;
        }
        opcode++;
    }
    zend_set_user_opcode_handler(opcode, sw_return_opcode_handler);
    memset(sw_return_op, 0, sizeof(sw_return_op));
    sw_return_op[0].opcode = opcode;
    zend_vm_set_opcode_handler_ex(sw_return_op, 0, 0, 0);

    memset(&sw_return_func, 0, sizeof(sw_return_func));
    sw_return_func.type = ZEND_USER_FUNCTION;
    sw_return_func.function_name = zend_string_init("return", sizeof("return") - 1, 1);
    sw_return_func.filename = ZSTR_EMPTY_ALLOC();
    sw_return_func.opcodes = sw_return_op;
    sw_return_func.last_try_catch = 1;
    sw_return_func.try_catch_array = &sw_terminate_try_catch_array;
    zend_vm_init_call_frame(&return_frame, ZEND_CALL_TOP_FUNCTION, (zend_function*) &sw_return_func, 0, NULL, NULL);
#if (ZEND_VM_KIND == ZEND_VM_KIND_HYBRID || (defined(ZEND_VM_FP_GLOBAL_REG) && defined(ZEND_VM_IP_GLOBAL_REG)))
    return_frame.opline = zend_get_halt_op();
#else
    return_frame.opline = sw_return_op;
#endif
    return_frame.return_value = NULL;
    return_frame.prev_execute_data = NULL;

    COROG.origin_vm_stack = EG(vm_stack);
    COROG.origin_vm_stack_top = EG(vm_stack_top);
    COROG.origin_vm_stack_end = EG(vm_stack_end);

    COROG.coro_num = 0;
    if (COROG.max_coro_num <= 0)
    {
        COROG.max_coro_num = DEFAULT_MAX_CORO_NUM;
    }
    if (COROG.stack_size <= 0)
    {
        COROG.stack_size = DEFAULT_STACK_SIZE;
    }

    COROG.require = 0;
    COROG.active = 1;
    SwooleWG.coro_timeout_list = swLinkedList_new(1, NULL);
    return 0;
}


void coro_check(TSRMLS_D)
{
    if (!COROG.require)
    {
        swoole_php_fatal_error(E_ERROR, "must be called in the coroutine.");
    }
}

void coro_destroy(TSRMLS_D)
{
    if (COROG.chan_pipe)
    {
        COROG.chan_pipe->close(COROG.chan_pipe);
        efree(COROG.chan_pipe);
        COROG.chan_pipe = NULL;
    }
}

static int sw_return_opcode_handler(zend_execute_data *execute_data)
{
    return ZEND_USER_OPCODE_RETURN;
}

static int sw_terminate_opcode_handler(zend_execute_data *execute_data)
{
    coro_task *task = (coro_task *) sw_get_current_task();
    ZEND_ASSERT(task != NULL);
    sw_coro_close(TSRMLS_C);
    return ZEND_USER_OPCODE_RETURN;
}

int php_coro_create(php_args *php_arg)
{
    zend_fcall_info_cache *fci_cache = php_arg->fci_cache;
    zval **argv = php_arg->argv;
    int argc = php_arg->argc;
    zval *retval = php_arg->retval;
    void *post_callback = php_arg->post_callback;
    void* params = php_arg->params;
    int cid = coroutine_get_cid();

    zend_function *func;
    uint32_t i;
    coro_task *task;

    zend_vm_stack origin_vm_stack = EG(vm_stack);
    zval *origin_vm_stack_top = EG(vm_stack_top);
    zval *origin_vm_stack_end = EG(vm_stack_end);

    func = fci_cache->function_handler;
    sw_vm_stack_init();
    zend_execute_data *call = (zend_execute_data *) (EG(vm_stack_top));

    task = (coro_task *) EG(vm_stack_top);
    EG(vm_stack_top) = (zval *) ((char *) call + TASK_SLOT * sizeof(zval));

    zend_execute_data *terminate_frame = (zend_execute_data*) EG(vm_stack_top);
    EG(vm_stack_top) = (zval*) terminate_frame + ZEND_CALL_FRAME_SLOT;
    zend_vm_init_call_frame(terminate_frame, ZEND_CALL_TOP_FUNCTION, (zend_function*) &sw_terminate_func, 0, NULL, NULL);
    terminate_frame->opline = sw_terminate_op;
    terminate_frame->call = NULL;
    terminate_frame->return_value = NULL;
    terminate_frame->prev_execute_data = &return_frame;

    call = zend_vm_stack_push_call_frame(ZEND_CALL_NESTED_FUNCTION | ZEND_CALL_DYNAMIC, func, argc,
            fci_cache->called_scope, fci_cache->object);

#if PHP_MINOR_VERSION < 1
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
    call->prev_execute_data = terminate_frame;

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

    COROG.call_stack[COROG.call_stack_size++] = task;
    COROG.current_coro = task;
    swTraceLog(SW_TRACE_COROUTINE, "Create coro id: %d, coro total count: %d, heap size: %zu", cid, COROG.coro_num, zend_memory_usage(0));

    EG(current_execute_data) = task->execute_data;
    EG(vm_stack) = task->stack;
    EG(vm_stack_top) = task->vm_stack_top;
    EG(vm_stack_end) = task->vm_stack_end;
    COROG.require = 1;
    zend_execute_ex(EG(current_execute_data) TSRMLS_CC);
    return 0;
}

void php_coro_create_callback(void *arg)
{
    php_args *php_arg = (php_args *) arg;
    php_coro_create(php_arg);
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
    php_args.post_callback = post_callback;
    php_args.params = params;

    COROG.error = 0;
    COROG.coro_num++;

    int ret = coroutine_create(php_coro_create_callback, (void*) &php_args);
    if (ret > 0)
    {
        return 0;
    }
    else
    {
        COROG.coro_num--;
        return ret;
    }
}

void sw_coro_save(zval *return_value, php_context *sw_current_context)
{
    SWCC(current_coro_return_value_ptr) = return_value;
    SWCC(current_execute_data) = EG(current_execute_data);
    SWCC(current_vm_stack) = EG(vm_stack);
    SWCC(current_vm_stack_top) = EG(vm_stack_top);
    SWCC(current_vm_stack_end) = EG(vm_stack_end);
    SWCC(current_task) = (coro_task *) sw_get_current_task();;
}

int sw_coro_resume(php_context *sw_current_context, zval *retval, zval *coro_retval)
{
    coro_task *task = SWCC(current_task);
    COROG.call_stack[COROG.call_stack_size++] = task;
    COROG.current_coro = task;
    swTraceLog(SW_TRACE_COROUTINE,"sw_coro_resume coro id %d", COROG.current_coro->cid);
    task->state = SW_CORO_RUNNING;
    EG(current_execute_data) = SWCC(current_execute_data);
    EG(vm_stack) = SWCC(current_vm_stack);
    EG(vm_stack_top) = SWCC(current_vm_stack_top);
    EG(vm_stack_end) = SWCC(current_vm_stack_end);
    COROG.require = 1;
    if (EG(current_execute_data)->prev_execute_data->opline->result_type != IS_UNUSED)
    {
        ZVAL_COPY(SWCC(current_coro_return_value_ptr), retval);
    }
    coroutine_resume(task->co);
    if (unlikely(EG(exception)))
    {
        sw_zval_ptr_dtor(&retval);
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    return CORO_END;
}

int sw_coro_resume_parent(php_context *sw_current_context, zval *retval, zval *coro_retval)
{
    EG(vm_stack) = SWCC(current_vm_stack);
    EG(vm_stack_top) = SWCC(current_vm_stack_top);
    EG(vm_stack_end) = SWCC(current_vm_stack_end);
    EG(current_execute_data) = SWCC(current_execute_data);
    COROG.current_coro = SWCC(current_task);
    return CORO_END;
}

void sw_coro_yield()
{
    coro_task *task = (coro_task *) sw_get_current_task();
    COROG.call_stack_size--;
    swTraceLog(SW_TRACE_COROUTINE,"coro_yield coro id %d", task->cid);
    task->state = SW_CORO_YIELD;
    task->is_yield = 1;
    EG(vm_stack) = task->origin_stack;
    EG(vm_stack_top) = task->origin_vm_stack_top;
    EG(vm_stack_end) = task->origin_vm_stack_end;
    coroutine_yield(task->co);
}

void sw_coro_close()
{
    coro_task *task = (coro_task *) sw_get_current_task();
    swTraceLog(SW_TRACE_COROUTINE,"coro_close coro id %d", task->cid);
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
    COROG.call_stack_size--;
    free_cidmap(task->cid);
    efree(task->stack);
    --COROG.coro_num;
    //COROG.current_coro = NULL;
    COROG.require = 0;
    swTraceLog(SW_TRACE_COROUTINE, "close coro and %d remained. usage size: %zu. malloc size: %zu", COROG.coro_num, zend_memory_usage(0), zend_memory_usage(1));
}

static coro_task* sw_get_current_task()
{
    return COROG.call_stack[COROG.call_stack_size - 1];
}

void coro_handle_timeout()
{
    swLinkedList *timeout_list = SwooleWG.coro_timeout_list;
    swTimer_node *tnode = NULL;
    if (timeout_list != NULL && timeout_list->num > 0)
    {
        php_context *cxt = (php_context *) swLinkedList_pop(timeout_list);
        while (cxt != NULL)
        {
            cxt->onTimeout(cxt);
            cxt = (php_context *) swLinkedList_pop(timeout_list);
        }
    }

    timeout_list = SwooleWG.delayed_coro_timeout_list;
    if (likely(timeout_list != NULL))
    {
        swTimer_coro_callback *scc = (swTimer_coro_callback *) swLinkedList_pop(timeout_list);
        while (scc != NULL)
        {
            php_context *context = (php_context *) scc->data;
            if (unlikely(context->state == SW_CORO_CONTEXT_TERM))
            {
                efree(context);
                efree(scc);
            }
            else
            {
                context->state = SW_CORO_CONTEXT_RUNNING;
                tnode = SwooleG.timer.add(&SwooleG.timer, scc->ms, 0, scc, php_swoole_onTimeout);

                if (tnode == NULL)
                {
                    efree(scc);
                    swWarn("Addtimer coro failed.");
                }
                else
                {
                    tnode->type = SW_TIMER_TYPE_CORO;
                    *scc->timeout_id = tnode->id;
                }
            }
            scc = (swTimer_coro_callback *) swLinkedList_pop(timeout_list);
        }
    }
}
#endif
