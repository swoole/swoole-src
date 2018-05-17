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
#include "php_swoole.h"
#include "swoole_coroutine.h"
#include "thirdparty/libco/co_routine.h"
#include "thirdparty/libco/co_routine_inner.h"
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
pthread_key_t key;

static int sw_terminate_opcode_handler(zend_execute_data *execute_data);
static int sw_return_opcode_handler(zend_execute_data *execute_data);

static zend_op_array sw_terminate_func;
static zend_try_catch_element sw_terminate_try_catch_array =
{ 0, 1, 0, 0 };
static zend_op sw_terminate_op[2];
static zend_op_array sw_return_func;
static zend_op sw_return_op[1];
zend_execute_data return_frame;

static void resume_php_stack(stCoRoutine_t *co);
static int alloc_cidmap();
static void free_cidmap(int cid);
static int libco_resume(stCoRoutine_t *co);
static int libco_yield();
static int libco_release(stCoRoutine_t *co);
static int libco_set_task(coro_task *task);
static coro_task *libco_get_task();

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

static void resume_php_stack(stCoRoutine_t *co)
{
    if (co)
    {
        coro_task *task;
        if (co->cIsMain)
        {
            task = (coro_task *) pthread_getspecific(key);
        }
        else
        {
            task = (coro_task *)co->aSpec[ key ].value;
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
    }
}

int coro_init(TSRMLS_D)
{
    pthread_key_create (&key,NULL);
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
    sw_terminate_func.function_name = zend_string_init("close_coro", sizeof("close_coro") - 1, 1);
    sw_terminate_func.filename = ZSTR_EMPTY_ALLOC();
    sw_terminate_func.opcodes = sw_terminate_op;
    sw_terminate_func.last_try_catch = 1;
    sw_terminate_func.try_catch_array = &sw_terminate_try_catch_array;

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

}

static int sw_return_opcode_handler(zend_execute_data *execute_data)
{
    return ZEND_USER_OPCODE_RETURN;
}

static int sw_terminate_opcode_handler(zend_execute_data *execute_data)
{
    coro_task * task = libco_get_task();
    ZEND_ASSERT(task != NULL);
    sw_coro_close(TSRMLS_C);
    EG(vm_stack) = task->origin_stack;
    EG(vm_stack_top) = task->origin_vm_stack_top;
    EG(vm_stack_end) = task->origin_vm_stack_end;
    task->state = SW_CORO_END;
    return ZEND_USER_OPCODE_RETURN;
}

//internal function api
static void *fn_coro_create(void *arg)
{
    php_args *php_arg = (php_args *)arg;
    int ret = sw_coro_create(php_arg->fci_cache, php_arg->argv, php_arg->argc, php_arg->retval, php_arg->post_callback,
            php_arg->params);
    return 0;
}

//cxx wrapper for internal function api
int libco_create(zend_fcall_info_cache *fci_cache, zval **argv, int argc, zval *retval, void *post_callback,
        void *params)
{
    php_args php_args;
    php_args.fci_cache = fci_cache;
    php_args.argv = argv;
    php_args.argc = argc;
    php_args.retval = retval;
    php_args.post_callback = post_callback;
    php_args.params = params;
    stCoRoutine_t *co = NULL;
    co_create(&co, NULL, fn_coro_create, &php_args);
    libco_resume(co);
    return 0;
}

static int libco_resume(stCoRoutine_t *co)
{
    co_resume(co);
    if (co->cEnd) {
        resume_php_stack(co);
        libco_release(co);
    }
    return 0;
}

static int libco_yield()
{
    co_yield_ct();
    return 0;
}

static int libco_release(stCoRoutine_t *co)
{
    co_release(co);
    return 0;
}

static int libco_set_task(coro_task *task)
{
    co_setspecific(key,task);
    return 0;
}

static coro_task *libco_get_task()
{
    coro_task *task = (coro_task *)co_getspecific(key);
    return task;
}
//wrapper end

int sw_coro_create(zend_fcall_info_cache *fci_cache, zval **argv, int argc, zval *retval, void *post_callback,
        void* params)
{
    int cid = alloc_cidmap();
    if (unlikely(COROG.coro_num >= COROG.max_coro_num) && unlikely(cid != -1))
    {
        swWarn("exceed max number of coro %d", COROG.coro_num);
        return CORO_LIMIT;
    }
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

    ++COROG.coro_num;
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
    task->state = SW_CORO_RUNNING;
    task->co = GetCurrThreadCo();
    libco_set_task(task);
    //compat history use in swoole
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

int sw_coro_save(zval *return_value, php_context *sw_current_context)
{
    SWCC(current_coro_return_value_ptr) = return_value;
    SWCC(current_execute_data) = EG(current_execute_data);
    SWCC(current_vm_stack) = EG(vm_stack);
    SWCC(current_vm_stack_top) = EG(vm_stack_top);
    SWCC(current_vm_stack_end) = EG(vm_stack_end);
    SWCC(current_task) = libco_get_task();
    return 0;
}

int sw_coro_resume(php_context *sw_current_context, zval *retval, zval *coro_retval)
{
    swTraceLog(SW_TRACE_COROUTINE,"sw_coro_resume coro id %d", COROG.current_coro->cid);
    coro_task *task = SWCC(current_task);
    COROG.current_coro = task;
    task->state = SW_CORO_RUNNING;
    EG(current_execute_data) = task->execute_data;
    EG(vm_stack) = task->stack;
    EG(vm_stack_top) = task->vm_stack_top;
    EG(vm_stack_end) = task->vm_stack_end;
    COROG.require = 1;
    if (EG(current_execute_data)->opline->result_type != IS_UNUSED)
    {
        ZVAL_COPY(SWCC(current_coro_return_value_ptr), retval);
    }
    libco_resume(task->co);
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

int sw_coro_yield()
{
    coro_task *task = libco_get_task();
    swTraceLog(SW_TRACE_COROUTINE,"coro_yield coro id %d", task->cid);
    task->state = SW_CORO_YIELD;
    task->is_yield = 1;
    EG(vm_stack) = task->origin_stack;
    EG(vm_stack_top) = task->origin_vm_stack_top;
    EG(vm_stack_end) = task->origin_vm_stack_end;
    libco_yield();
    return 0;
}

void sw_coro_close()
{
    coro_task *task = libco_get_task();
    swTraceLog(SW_TRACE_COROUTINE,"coro_close coro id %d", task->cid);
    free_cidmap(task->cid);
    efree(task->stack);
    --COROG.coro_num;
    swTraceLog(SW_TRACE_COROUTINE, "close coro and %d remained. usage size: %zu. malloc size: %zu", COROG.coro_num, zend_memory_usage(0), zend_memory_usage(1));
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
//==========================================
struct task_test
{
    stCoRoutine_t *co;
    int fd;
};


static void *routine_suba()
{
    printf("routine_suba 1\n");
    return 0;
}

static void *routine_a( void *arg )
{
    //task_test *co = (task_test*)arg;

    printf("routine_a 1\n");
    printf("routine_a 2\n");
    routine_suba();
    co_yield_ct();
    printf("routine_a 3\n");
    return 0;
}

static void *routine_b( void *arg )
{
    //task_test *co = (task_test*)arg;

    printf("routine_b 1\n");
    printf("routine_b 2\n");
    co_yield_ct();
    printf("routine_b 3\n");
    return 0;
}

int sw_coro_test()
{
    task_test * task_a = (task_test*) calloc(1, sizeof(task_test));
    task_test * task_b = (task_test*) calloc(1, sizeof(task_test));
    printf("main start\n");
    co_create(&(task_a->co), NULL, routine_a, task_a);
    co_create(&(task_b->co), NULL, routine_b, task_b);
    printf("resume \n");
    co_resume(task_a->co);
    printf("main \n");
    co_resume(task_b->co);
    printf("main \n");
    co_resume(task_a->co);
    printf("main \n");
    co_resume(task_b->co);
    printf("main end\n");
    return 0;
}
