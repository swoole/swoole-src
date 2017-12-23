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
  +----------------------------------------------------------------------+
 */

#include "php_swoole.h"
#include "zend_API.h"
#include "ext/standard/php_lcg.h"

#ifdef SW_COROUTINE
#include "swoole_coroutine.h"

#define SWCC(x) sw_current_context->x

jmp_buf *swReactorCheckPoint = NULL;
coro_global COROG;

static int alloc_cidmap();
static void free_cidmap(int cid);

int coro_init(TSRMLS_D)
{
#if PHP_MAJOR_VERSION < 7
    COROG.origin_vm_stack = EG(argument_stack);
#else
    COROG.origin_vm_stack = EG(vm_stack);
    COROG.origin_vm_stack_top = EG(vm_stack_top);
    COROG.origin_vm_stack_end = EG(vm_stack_end);
#endif
    COROG.origin_ex = EG(current_execute_data);
    COROG.coro_num = 0;
    if (COROG.max_coro_num <= 0)
    {
        COROG.max_coro_num = DEFAULT_MAX_CORO_NUM;
    }
    COROG.require = 0;
    swReactorCheckPoint = emalloc(sizeof(jmp_buf));
    return 0;
}

void coro_check(TSRMLS_D)
{
	if (!COROG.require)
	{
        swoole_php_fatal_error(E_ERROR, "coroutine client should use under swoole server in onRequet, onReceive, onConnect callback.");
	}
}

#if PHP_MAJOR_VERSION < 7
int sw_coro_create(zend_fcall_info_cache *fci_cache, zval **argv, int argc, zval **retval, void *post_callback, void* params)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
    int cid = alloc_cidmap();
    if (unlikely(COROG.coro_num >= COROG.max_coro_num) && unlikely(cid != -1))
    {
        swWarn("exceed max number of coro %d", COROG.coro_num);
        return CORO_LIMIT;
    }
    zend_op_array *op_array = (zend_op_array *)fci_cache->function_handler;
    zend_execute_data *execute_data;
    size_t execute_data_size = ZEND_MM_ALIGNED_SIZE(sizeof(zend_execute_data));
    size_t CVs_size = ZEND_MM_ALIGNED_SIZE(sizeof(zval **) * op_array->last_var * 2);
    size_t Ts_size = ZEND_MM_ALIGNED_SIZE(sizeof(temp_variable)) * op_array->T;
    size_t call_slots_size = ZEND_MM_ALIGNED_SIZE(sizeof(call_slot)) * op_array->nested_calls;
    size_t stack_size = ZEND_MM_ALIGNED_SIZE(sizeof(zval*)) * op_array->used_stack;
    size_t task_size = ZEND_MM_ALIGNED_SIZE(sizeof(coro_task));
    size_t total_size = execute_data_size + Ts_size + CVs_size + call_slots_size + stack_size;

    //from generator
    size_t args_size = ZEND_MM_ALIGNED_SIZE(sizeof(zval*)) * (argc + 1);

    total_size += execute_data_size + args_size + task_size;

    EG(active_symbol_table) = NULL;
    EG(argument_stack) = zend_vm_stack_new_page((total_size + (sizeof(void*) - 1)) / sizeof(void*));
    EG(argument_stack)->prev = NULL;
    execute_data = (zend_execute_data*)((char*)ZEND_VM_STACK_ELEMETS(EG(argument_stack)) + args_size + Ts_size + execute_data_size + task_size);

    /* copy prev_execute_data */
    execute_data->prev_execute_data = (zend_execute_data*)((char*)ZEND_VM_STACK_ELEMETS(EG(argument_stack)) + args_size + task_size);
    memset(execute_data->prev_execute_data, 0, sizeof(zend_execute_data));
    execute_data->prev_execute_data->function_state.function = (zend_function*)op_array;
    execute_data->prev_execute_data->function_state.arguments = (void**)((char*)ZEND_VM_STACK_ELEMETS(EG(argument_stack)) + ZEND_MM_ALIGNED_SIZE(sizeof(zval*)) * argc + task_size);

    /* copy arguments */
    *execute_data->prev_execute_data->function_state.arguments = (void*)(zend_uintptr_t)argc;
    if (argc > 0)
    {
      zval **arg_dst = (zval**)zend_vm_stack_get_arg_ex(execute_data->prev_execute_data, 1);
      int i;
      for (i = 0; i < argc; i++)
      {
        arg_dst[i] = argv[i];
        Z_ADDREF_P(arg_dst[i]);
      }
    }
    memset(EX_CV_NUM(execute_data, 0), 0, sizeof(zval **) * op_array->last_var);
    execute_data->call_slots = (call_slot*)((char *)execute_data + execute_data_size + CVs_size);
    execute_data->op_array = op_array;

    EG(argument_stack)->top = zend_vm_stack_frame_base(execute_data);

    execute_data->object = NULL;
    execute_data->current_this = NULL;
    execute_data->old_error_reporting = NULL;
    execute_data->symbol_table = NULL;
    execute_data->call = NULL;
    execute_data->nested = 0;
	execute_data->original_return_value = NULL;
	execute_data->fast_ret = NULL;
#if PHP_API_VERSION >= 20131106
	execute_data->delayed_exception = NULL;
#endif

    if (!op_array->run_time_cache && op_array->last_cache_slot)
    {
      op_array->run_time_cache = ecalloc(op_array->last_cache_slot, sizeof(void*));
    }

    if (fci_cache->object_ptr)
    {
        EG(This) = fci_cache->object_ptr;
        execute_data->object = EG(This);
        if (!PZVAL_IS_REF(EG(This)))
        {
            Z_ADDREF_P(EG(This));
        }
        else
        {
            zval *this_ptr;
            ALLOC_ZVAL(this_ptr);
            *this_ptr = *EG(This);
            INIT_PZVAL(this_ptr);
            zval_copy_ctor(this_ptr);
            EG(This) = this_ptr;
        }
    }
    else
    {
        EG(This) = NULL;
    }

    if (op_array->this_var != -1 && EG(This))
    {
        Z_ADDREF_P(EG(This)); /* For $this pointer */
        if (!EG(active_symbol_table))
        {
            SW_EX_CV(op_array->this_var) = (zval **) SW_EX_CV_NUM(execute_data, op_array->last_var + op_array->this_var);
            *SW_EX_CV(op_array->this_var) = EG(This);
        }
        else
        {
            if (zend_hash_add(EG(active_symbol_table), "this", sizeof("this"), &EG(This), sizeof(zval *), (void **) EX_CV_NUM(execute_data, op_array->this_var))==FAILURE)
            {
                Z_DELREF_P(EG(This));
            }
        }
    }

    execute_data->opline = op_array->opcodes;
    EG(opline_ptr) = &((*execute_data).opline);

    execute_data->function_state.function = (zend_function *) op_array;
    execute_data->function_state.arguments = NULL;

    EG(active_op_array) = op_array;

    EG(current_execute_data) = execute_data;
    EG(return_value_ptr_ptr) = (zval **)emalloc(sizeof(zval *));
    EG(scope) = fci_cache->calling_scope;
    EG(called_scope) = fci_cache->called_scope;
    ++COROG.coro_num;
    COROG.current_coro = (coro_task *)ZEND_VM_STACK_ELEMETS(EG(argument_stack));

    int coro_status;
    COROG.current_coro->cid = cid;
    COROG.current_coro->start_time = time(NULL);
    COROG.current_coro->function = NULL;
    COROG.current_coro->post_callback = post_callback;
    COROG.current_coro->post_callback_params = params;
    COROG.require = 1;
    if (!setjmp(*swReactorCheckPoint))
    {
        zend_execute_ex(execute_data TSRMLS_CC);
        if (EG(return_value_ptr_ptr) != NULL)
        {
            *retval = *EG(return_value_ptr_ptr);
        }
        coro_close(TSRMLS_C);
        swTrace("create the %d coro with stack %zu. heap size: %zu\n", COROG.coro_num, total_size, zend_memory_usage(0 TSRMLS_CC));
        coro_status = CORO_END;
    }
    else
    {
        coro_status = CORO_YIELD;
    }
    COROG.require = 0;

    return coro_status;
}

#else
#define TASK_SLOT \
    ((int)((ZEND_MM_ALIGNED_SIZE(sizeof(coro_task)) + ZEND_MM_ALIGNED_SIZE(sizeof(zval)) - 1) / ZEND_MM_ALIGNED_SIZE(sizeof(zval))))

int sw_coro_create(zend_fcall_info_cache *fci_cache, zval **argv, int argc, zval *retval, void *post_callback, void* params)
{
    int cid = alloc_cidmap();
    if (unlikely(COROG.coro_num >= COROG.max_coro_num) && unlikely(cid != -1))
    {
        swWarn("exceed max number of coro %d", COROG.coro_num);
        return CORO_LIMIT;
    }
    zend_function *func = fci_cache->function_handler;
    zend_op_array *op_array = (zend_op_array *) fci_cache->function_handler;
    zend_object *object;
    int i;
    zend_vm_stack_init();

    COROG.current_coro = (coro_task *) EG(vm_stack_top);
    zend_execute_data *call = (zend_execute_data *) (EG(vm_stack_top));
    EG(vm_stack_top) = (zval *) ((char *) call + TASK_SLOT * sizeof(zval));
    object = (func->common.fn_flags & ZEND_ACC_STATIC) ? NULL : fci_cache->object;
    call = zend_vm_stack_push_call_frame(ZEND_CALL_TOP_FUNCTION | ZEND_CALL_ALLOCATED, fci_cache->function_handler, argc, fci_cache->called_scope, object);

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
    SW_ALLOC_INIT_ZVAL(retval);
    COROG.allocated_return_value_ptr = retval;
    EG(current_execute_data) = NULL;
    zend_init_execute_data(call, op_array, retval);

    ++COROG.coro_num;
    COROG.current_coro->cid = cid;
    COROG.current_coro->start_time = time(NULL);
    COROG.current_coro->function = NULL;
    COROG.current_coro->post_callback = post_callback;
    COROG.current_coro->post_callback_params = params;
    COROG.require = 1;

    int coro_status;
    if (!setjmp(*swReactorCheckPoint))
    {
        zend_execute_ex(call);
        coro_close(TSRMLS_C);
        swTrace("Create the %d coro with stack. heap size: %zu\n", COROG.coro_num, zend_memory_usage(0));
        coro_status = CORO_END;
    }
    else
    {
        coro_status = CORO_YIELD;
    }
    COROG.require = 0;
    return coro_status;
}
#endif

#if PHP_MAJOR_VERSION < 7
sw_inline void coro_close(TSRMLS_D)
{
    if (COROG.current_coro->post_callback)
    {
        COROG.current_coro->post_callback(COROG.current_coro->post_callback_params);
    }
    free_cidmap(COROG.current_coro->cid);
    if (COROG.current_coro->function)
    {
        sw_zval_free(COROG.current_coro->function);
    }

    void **arguments = EG(current_execute_data)->function_state.arguments;

    if (arguments)
    {
        int arg_count = (int)(zend_uintptr_t)(*arguments);
        zval **arg_start = (zval **)(arguments - arg_count);
        int i;
        for (i = 0; i < arg_count; ++i)
        {
            zval_ptr_dtor(arg_start + i);
        }
    }

    if (EG(active_symbol_table))
    {
        if (EG(symtable_cache_ptr) >= EG(symtable_cache_limit))
        {
            zend_hash_destroy(EG(active_symbol_table));
            efree(EG(active_symbol_table));
        }
        else
        {
            zend_hash_clean(EG(active_symbol_table));
            *(++EG(symtable_cache_ptr)) = EG(active_symbol_table);
        }
        EG(active_symbol_table) = NULL;
    }

    if (EG(return_value_ptr_ptr))
    {
        efree(EG(return_value_ptr_ptr));
    }
    efree(EG(argument_stack));
    EG(argument_stack) = COROG.origin_vm_stack;
    EG(current_execute_data) = COROG.origin_ex;
    --COROG.coro_num;
    swTrace("closing coro and %d remained. usage size: %zu. malloc size: %zu", COROG.coro_num, zend_memory_usage(0 TSRMLS_CC), zend_memory_usage(1 TSRMLS_CC));
    
    return;
}
#else
sw_inline void coro_close(TSRMLS_D)
{
    swTraceLog(SW_TRACE_COROUTINE, "Close coroutine id %d", COROG.current_coro->cid);
    if (COROG.current_coro->function)
    {
        sw_zval_free(COROG.current_coro->function);
        COROG.current_coro->function = NULL;
    }
    free_cidmap(COROG.current_coro->cid);
    efree(EG(vm_stack));
    efree(COROG.allocated_return_value_ptr);
    EG(vm_stack) = COROG.origin_vm_stack;
    EG(vm_stack_top) = COROG.origin_vm_stack_top;
    EG(vm_stack_end) = COROG.origin_vm_stack_end;
    --COROG.coro_num;
    COROG.current_coro = NULL;
    swTraceLog(SW_TRACE_COROUTINE, "closing coro and %d remained. usage size: %zu. malloc size: %zu", COROG.coro_num, zend_memory_usage(0), zend_memory_usage(1));
}
#endif

#if PHP_MAJOR_VERSION < 7
sw_inline php_context *sw_coro_save(zval *return_value, zval **return_value_ptr, php_context *sw_current_context)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
    SWCC(current_coro_return_value_ptr_ptr) = return_value_ptr;
    SWCC(current_coro_return_value_ptr) = return_value;
    SWCC(current_eg_return_value_ptr_ptr) = EG(return_value_ptr_ptr);
    SWCC(current_execute_data) = EG(current_execute_data);
    SWCC(current_opline_ptr) = EG(opline_ptr);
    SWCC(current_opline) = *(EG(opline_ptr));
    SWCC(current_active_op_array) = EG(active_op_array);
    SWCC(current_active_symbol_table) = EG(active_symbol_table);
    SWCC(current_this) = EG(This);
    SWCC(current_scope) = EG(scope);
    SWCC(current_called_scope) = EG(called_scope);
    SWCC(current_vm_stack) = EG(argument_stack);
    SWCC(current_task) = COROG.current_coro;

    return sw_current_context;
}
#else
sw_inline php_context *sw_coro_save(zval *return_value, php_context *sw_current_context)
{
    SWCC(current_coro_return_value_ptr) = return_value;
    SWCC(current_execute_data) = EG(current_execute_data);
    SWCC(current_vm_stack) = EG(vm_stack);
    SWCC(current_vm_stack_top) = EG(vm_stack_top);
    SWCC(current_vm_stack_end) = EG(vm_stack_end);
    SWCC(current_task) = COROG.current_coro;
    SWCC(allocated_return_value_ptr) = COROG.allocated_return_value_ptr;

    return sw_current_context;

}
#endif

#if PHP_MAJOR_VERSION < 7
int sw_coro_resume(php_context *sw_current_context, zval *retval, zval **coro_retval)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
    //free unused return value
    zval *saved_return_value = sw_current_context->current_coro_return_value_ptr;
    zend_bool unused = sw_current_context->current_execute_data->opline->result_type & EXT_TYPE_UNUSED;
    sw_current_context->current_execute_data->opline++;
    if (SWCC(current_this))
    {
        zval_ptr_dtor(&SWCC(current_this));
    }
    EG(return_value_ptr_ptr) = SWCC(current_eg_return_value_ptr_ptr);
    *(sw_current_context->current_coro_return_value_ptr) = *retval;
    zval_copy_ctor(sw_current_context->current_coro_return_value_ptr);
    EG(current_execute_data) = SWCC(current_execute_data);
    EG(opline_ptr) = SWCC(current_opline_ptr);
    EG(active_op_array) = SWCC(current_active_op_array)  ;
    EG(active_symbol_table) = SWCC(current_active_symbol_table);
    EG(This) = EG(current_execute_data)->current_this;
    EG(scope) = EG(current_execute_data)->current_scope;
    EG(called_scope) = EG(current_execute_data)->current_called_scope;
    EG(argument_stack) = SWCC(current_vm_stack);

    sw_current_context->current_execute_data->call--;
    zend_vm_stack_clear_multiple(1 TSRMLS_CC);
    COROG.current_coro = SWCC(current_task);
    COROG.require = 1;

    int coro_status;
    if (!setjmp(*swReactorCheckPoint))
    {
        //coro exit
        zend_execute_ex(sw_current_context->current_execute_data TSRMLS_CC);
        if (EG(return_value_ptr_ptr) != NULL)
        {
            *coro_retval = *EG(return_value_ptr_ptr);
        }
        coro_close(TSRMLS_C);
        coro_status = CORO_END;
    }
    else
    {
        //coro yield
        coro_status = CORO_YIELD;
    }
    COROG.require = 0;
    if (unused)
    {
        sw_zval_ptr_dtor(&saved_return_value);
    }
    if (unlikely(coro_status == CORO_END && EG(exception)))
    {
        sw_zval_ptr_dtor(&retval);
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    return coro_status;
}
#else
int sw_coro_resume(php_context *sw_current_context, zval *retval, zval *coro_retval)
{
    EG(vm_stack) = SWCC(current_vm_stack);
    EG(vm_stack_top) = SWCC(current_vm_stack_top);
    EG(vm_stack_end) = SWCC(current_vm_stack_end);

    zend_execute_data *current = SWCC(current_execute_data);
    if (ZEND_CALL_INFO(current) & ZEND_CALL_RELEASE_THIS)
    {
        zval_ptr_dtor(&(current->This));
    }
    zend_vm_stack_free_args(current);
    zend_vm_stack_free_call_frame(current);

    EG(current_execute_data) = current->prev_execute_data;
    COROG.current_coro = SWCC(current_task);
    COROG.require = 1;
#if PHP_MINOR_VERSION < 1
    EG(scope) = EG(current_execute_data)->func->op_array.scope;
#endif
    COROG.allocated_return_value_ptr = SWCC(allocated_return_value_ptr);
    if (EG(current_execute_data)->opline->result_type != IS_UNUSED)
    {
        ZVAL_COPY(SWCC(current_coro_return_value_ptr), retval);
    }
    EG(current_execute_data)->opline++;

    int coro_status;
    if (!setjmp(*swReactorCheckPoint))
    {
        //coro exit
        zend_execute_ex(EG(current_execute_data) TSRMLS_CC);
        coro_close(TSRMLS_C);
        coro_status = CORO_END;
    }
    else
    {
        //coro yield
        coro_status = CORO_YIELD;
    }
    COROG.require = 0;

    if (unlikely(coro_status == CORO_END && EG(exception)))
    {
        sw_zval_ptr_dtor(&retval);
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    return coro_status;
}

int sw_coro_resume_parent(php_context *sw_current_context, zval *retval, zval *coro_retval)
{
    EG(vm_stack) = SWCC(current_vm_stack);
    EG(vm_stack_top) = SWCC(current_vm_stack_top);
    EG(vm_stack_end) = SWCC(current_vm_stack_end);

    EG(current_execute_data) = SWCC(current_execute_data);
    COROG.current_coro = SWCC(current_task);
    COROG.allocated_return_value_ptr = SWCC(allocated_return_value_ptr);
    return CORO_END;
}
#endif

sw_inline void coro_yield()
{
    SWOOLE_GET_TSRMLS;
#if PHP_MAJOR_VERSION >= 7
    EG(vm_stack) = COROG.origin_vm_stack;
    EG(vm_stack_top) = COROG.origin_vm_stack_top;
    EG(vm_stack_end) = COROG.origin_vm_stack_end;
#else
    EG(argument_stack) = COROG.origin_vm_stack;
    EG(current_execute_data) = COROG.origin_ex;
#endif
    longjmp(*swReactorCheckPoint, 1);
}

sw_inline void coro_handle_timeout()
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

/* allocate cid for coroutine */
typedef struct cidmap 
{
    uint32_t nr_free;
    char page[4096];
} cidmap_t;

/* 1 <= cid <= 32768 */
static cidmap_t cidmap = { 0x8000, {0} };

static int last_cid = -1;

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
static int find_next_zero_bit(void *addr, int cid)
{
    uint32_t *p;
    uint32_t mask;
    int mark = cid;

    cid++;
    cid &= 0x7fff;
    while (cid != mark)
    {
        mask = 1U << (cid & 0x1f);
        p = ((uint32_t*)addr) + (cid >> 5);

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

static void free_cidmap(int cid)
{
    cid--;
    cidmap.nr_free++;
    clear_bit(cid, &cidmap.page);
}
#endif

