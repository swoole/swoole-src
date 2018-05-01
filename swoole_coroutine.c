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
#include "zend_API.h"

#ifdef SW_COROUTINE
#include "swoole_coroutine.h"
#include "zend_vm.h"
#include "zend_interfaces.h"
#include "zend_exceptions.h"
#include "zend_closures.h"

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

static void (*orig_interrupt_function)(zend_execute_data *execute_data);
static void sw_interrupt_function(zend_execute_data *execute_data);
static int sw_terminate_opcode_handler(zend_execute_data *execute_data);
static int sw_close_opcode_handler(zend_execute_data *execute_data);

static zend_op_array sw_terminate_func;
static zend_try_catch_element sw_terminate_try_catch_array =
{ 0, 1, 0, 0 };
static zend_op sw_terminate_op[2];
static zend_op_array sw_close_func;
static zend_op sw_close_op[1];
zend_execute_data fake_frame, dummy_frame;

static int alloc_cidmap();
static void free_cidmap(int cid);

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
    orig_interrupt_function = zend_interrupt_function;
    zend_interrupt_function = sw_interrupt_function;

    zend_uchar opcode = ZEND_VM_LAST_OPCODE + 1;
    while (1)
    {
        if (opcode == 255)
        {
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
    sw_terminate_func.function_name = zend_string_init("go", sizeof("go") - 1, 1);
    sw_terminate_func.filename = ZSTR_EMPTY_ALLOC();
    sw_terminate_func.opcodes = sw_terminate_op;
    sw_terminate_func.last_try_catch = 1;
    sw_terminate_func.try_catch_array = &sw_terminate_try_catch_array;

    zend_vm_init_call_frame(&fake_frame, ZEND_CALL_TOP_FUNCTION, NULL, 0, NULL, NULL);
#if PHP_MAJOR_VERSION >= 7 && PHP_MINOR_VERSION >= 2
    fake_frame.opline = zend_get_halt_op();
#else
    fake_frame.call = NULL;
#endif
    fake_frame.return_value = NULL;
    fake_frame.prev_execute_data = NULL;

    COROG.origin_ex = &fake_frame;
    COROG.origin_vm_stack = EG(vm_stack);
    COROG.origin_vm_stack_top = EG(vm_stack_top);
    COROG.origin_vm_stack_end = EG(vm_stack_end);

    while (1)
    {
        if (opcode == 255)
        {
            return FAILURE;
        }
        else if (zend_get_user_opcode_handler(opcode) == NULL)
        {
            break;
        }
        opcode++;
    }
    zend_set_user_opcode_handler(opcode, sw_close_opcode_handler);

    memset(sw_close_op, 0, sizeof(sw_close_op));
    sw_close_op[0].opcode = opcode;
    zend_vm_set_opcode_handler_ex(sw_close_op, 0, 0, 0);

    memset(&sw_close_func, 0, sizeof(sw_close_func));
    sw_close_func.type = ZEND_USER_FUNCTION;
    sw_close_func.function_name = zend_string_init("close", sizeof("close") - 1, 1);
    sw_close_func.filename = ZSTR_EMPTY_ALLOC();
    sw_close_func.opcodes = sw_close_op;
    sw_close_func.last_try_catch = 1;
    sw_close_func.try_catch_array = &sw_terminate_try_catch_array;

    zend_vm_init_call_frame(&dummy_frame, ZEND_CALL_TOP_FUNCTION, (zend_function*) &sw_close_func, 0, NULL, NULL);
    dummy_frame.opline = sw_close_op;
    dummy_frame.call = NULL;
    dummy_frame.return_value = NULL;
    dummy_frame.prev_execute_data = &fake_frame;

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

void coro_destroy(TSRMLS_D)
{

}

static int sw_terminate_opcode_handler(zend_execute_data *execute_data)
{
    coro_task *current_coro = COROG.current_coro;
    ZEND_ASSERT(current_coro != NULL);
    COROG.next_coro = NULL;
    current_coro->state = SW_CORO_END;
    EG(current_execute_data) = execute_data->prev_execute_data;
    return ZEND_USER_OPCODE_ENTER;
}

static int sw_close_opcode_handler(zend_execute_data *execute_data)
{
    coro_task *current_coro = COROG.current_coro;
    ZEND_ASSERT(current_coro != NULL);
    coro_close(TSRMLS_C);
    EG(current_execute_data) = execute_data->prev_execute_data;
    EG(vm_stack) = COROG.origin_vm_stack;
    EG(vm_stack_top) = COROG.origin_vm_stack_top;
    EG(vm_stack_end) = COROG.origin_vm_stack_end;
    return ZEND_USER_OPCODE_RETURN;
}

void coro_check(TSRMLS_D)
{
    if (!COROG.require)
    {
        swoole_php_fatal_error(E_ERROR, "must be called in the coroutine.");
    }
}

int sw_coro_create(zend_fcall_info_cache *fci_cache, zval **argv, int argc, zval *retval, void *post_callback,
        void* params)
{
    int cid = alloc_cidmap();
    if (unlikely(COROG.coro_num >= COROG.max_coro_num) && unlikely(cid != -1))
    {
        swWarn("exceed max number of coro %d", COROG.coro_num);
        return CORO_LIMIT;
    }
    COROG.call_stack_size++;
    zend_function *func;
    uint32_t i;

    func = fci_cache->function_handler;
    sw_vm_stack_init();

    /* func_stack start pos  vm stack_end*/
    zend_execute_data *call = (zend_execute_data *) (EG(vm_stack_top));
    /*coro_frame*/
    COROG.root_coro = (coro_task *) EG(vm_stack_top);
    EG(vm_stack_top) = (zval *) ((char *) call + TASK_SLOT * sizeof(zval));

    zend_execute_data *coro_frame = (zend_execute_data*) EG(vm_stack_top);
    EG(vm_stack_top) = (zval*) coro_frame + ZEND_CALL_FRAME_SLOT;
    zend_vm_init_call_frame(coro_frame, ZEND_CALL_TOP_FUNCTION, (zend_function*) &sw_terminate_func, 0, NULL, NULL);
    coro_frame->opline = sw_terminate_op;
    coro_frame->call = NULL;
    coro_frame->return_value = NULL;
    coro_frame->prev_execute_data = &dummy_frame;

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
    call->prev_execute_data = coro_frame;

    ++COROG.coro_num;
    COROG.root_coro->cid = cid;
    COROG.root_coro->execute_data = call;
    COROG.root_coro->stack = EG(vm_stack);
    COROG.root_coro->vm_stack_top = EG(vm_stack_top);
    COROG.root_coro->vm_stack_end = EG(vm_stack_end);
    COROG.root_coro->state = SW_CORO_INIT;
    COROG.root_coro->start_time = time(NULL);
    COROG.root_coro->function = NULL;
    COROG.root_coro->post_callback = post_callback;
    COROG.root_coro->post_callback_params = params;
    COROG.root_coro->has_yield = 0;
    COROG.require = 1;
    if (COROG.call_stack_size > 1 && COROG.current_coro)
    {
        COROG.root_coro->origin_coro = COROG.current_coro;
    }
    else
    {
        COROG.root_coro->origin_coro = NULL;
    }

    swTraceLog(SW_TRACE_COROUTINE, "Create coro id: %d, coro total count: %d, heap size: %zu", cid, COROG.coro_num, zend_memory_usage(0));

    coro_task *coro = COROG.root_coro;
    EG(current_execute_data) = coro->execute_data;
    EG(vm_stack) = coro->stack;
    EG(vm_stack_top) = coro->vm_stack_top;
    EG(vm_stack_end) = coro->vm_stack_end;
    coro->state = SW_CORO_RUNNING;
    COROG.require = 1;
    COROG.current_coro = coro;
    zend_execute_ex(EG(current_execute_data) TSRMLS_CC);
    COROG.call_stack_size--;
    return 0;
}

sw_inline void coro_close(TSRMLS_D)
{
    swTraceLog(SW_TRACE_COROUTINE,"coro_close coro id %d", COROG.current_coro->cid);
    free_cidmap(COROG.current_coro->cid);
    coro_task *current_coro = COROG.current_coro;
    if (current_coro && COROG.call_stack_size > 1 && current_coro->has_yield == 0)
    {
        COROG.current_coro = current_coro->origin_coro;
    } else
    {
        COROG.current_coro = NULL;
    }
    efree(current_coro->stack);
    --COROG.coro_num;
    swTraceLog(SW_TRACE_COROUTINE, "close coro and %d remained. usage size: %zu. malloc size: %zu", COROG.coro_num, zend_memory_usage(0), zend_memory_usage(1));
}

sw_inline php_context *sw_coro_save(zval *return_value, php_context *sw_current_context)
{
    SWCC(current_coro_return_value_ptr) = return_value;
    SWCC(current_execute_data) = EG(current_execute_data);
    SWCC(current_vm_stack) = EG(vm_stack);
    SWCC(current_vm_stack_top) = EG(vm_stack_top);
    SWCC(current_vm_stack_end) = EG(vm_stack_end);
    SWCC(current_task) = COROG.current_coro;
    return sw_current_context;
}

int sw_coro_resume(php_context *sw_current_context, zval *retval, zval *coro_retval)
{
    COROG.current_coro = SWCC(current_task);
    swTraceLog(SW_TRACE_COROUTINE,"sw_coro_resume coro id %d", COROG.current_coro->cid);
    COROG.current_coro->state = SW_CORO_RUNNING;
    EG(current_execute_data) = COROG.current_coro->execute_data;

    EG(vm_stack) = COROG.current_coro->stack;
    EG(vm_stack_top) = COROG.current_coro->vm_stack_top;
    EG(vm_stack_end) = COROG.current_coro->vm_stack_end;
    COROG.require = 1;
#if PHP_MINOR_VERSION < 1
    EG(scope) = EG(current_execute_data)->func->op_array.scope;
#endif
    EG(current_execute_data)->opline--;
    if (EG(current_execute_data)->opline->result_type != IS_UNUSED)
    {
        sw_zval_add_ref(&retval);
        ZVAL_COPY(SWCC(current_coro_return_value_ptr), retval);
    }
    EG(current_execute_data)->opline++;
    EG(vm_interrupt) = 0;
    zend_execute_ex(EG(current_execute_data) TSRMLS_CC);
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

sw_inline void coro_yield()
{
    swTraceLog(SW_TRACE_COROUTINE,"coro_yield coro id %d", COROG.current_coro->cid);
    SWOOLE_GET_TSRMLS;
    COROG.next_coro = NULL;
    COROG.pending_interrupt = 1;
    EG(vm_interrupt) = 1;
}

void sw_interrupt_function(zend_execute_data *execute_data)
{
    if (COROG.pending_interrupt)
    {
        COROG.pending_interrupt = 0;

        coro_task *current_coro;
        coro_task *coro;
        current_coro = COROG.current_coro;
        if (current_coro)
        {
            /* Suspend current coro */
            if (EXPECTED(current_coro->state == SW_CORO_RUNNING))
            {
                current_coro->execute_data = execute_data;
                current_coro->state = SW_CORO_SUSPENDED;
                current_coro->stack = EG(vm_stack);
                current_coro->vm_stack_top = EG(vm_stack_top);
                current_coro->vm_stack_end = EG(vm_stack_end);
                if (current_coro && COROG.call_stack_size > 1 && current_coro->has_yield == 0)
                {
                    COROG.current_coro = current_coro->origin_coro;
                }
            }
        }
        coro = COROG.next_coro;
        if (coro)
        {
            EG(current_execute_data) = coro->execute_data;
            EG(vm_stack) = coro->stack;
            EG(vm_stack_top) = coro->vm_stack_top;
            EG(vm_stack_end) = coro->vm_stack_end;
            coro->state = SW_CORO_RUNNING;
        }
        else
        {
            EG(current_execute_data) = COROG.origin_ex;
            if (current_coro && COROG.call_stack_size > 1 && current_coro->has_yield == 0)
            {
                EG(vm_stack) = current_coro->origin_coro->stack;
                EG(vm_stack_top) = current_coro->origin_coro->vm_stack_top;
                EG(vm_stack_end) = current_coro->origin_coro->vm_stack_end;
            }
            else
            {
                EG(vm_stack) = COROG.origin_vm_stack;
                EG(vm_stack_top) = COROG.origin_vm_stack_top;
                EG(vm_stack_end) = COROG.origin_vm_stack_end;
            }
            current_coro->has_yield = 1;
        }
        COROG.require = 1;
        COROG.next_coro = NULL;
//        if (UNEXPECTED(EG(exception)))
//        {
//            zend_rethrow_exception(EG(current_execute_data));
//        }
    }
    if (orig_interrupt_function)
    {
        orig_interrupt_function(execute_data);
    }
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
    char page[65536];
} cidmap_t;

/* 1 <= cid <= 524288 */
static cidmap_t cidmap =
{ MAX_CORO_NUM_LIMIT,
{ 0 } };

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

static void free_cidmap(int cid)
{
    cid--;
    cidmap.nr_free++;
    clear_bit(cid, &cidmap.page);
}
#endif
