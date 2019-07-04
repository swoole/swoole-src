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
  |         Twosee  <twose@qq.com>                                       |
  |         Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
 */

#include "php_swoole_cxx.h"
#include "swoole_coroutine_scheduler.h"
#include "swoole_coroutine_system.h"

#include "zend_builtin_functions.h"
#include "ext/spl/spl_array.h"

#include <unordered_map>

using swoole::coroutine::System;
using swoole::coroutine::Socket;
using swoole::Coroutine;
using swoole::PHPCoroutine;
using std::unordered_map;

#define PHP_CORO_TASK_SLOT ((int)((ZEND_MM_ALIGNED_SIZE(sizeof(php_coro_task)) + ZEND_MM_ALIGNED_SIZE(sizeof(zval)) - 1) / ZEND_MM_ALIGNED_SIZE(sizeof(zval))))

enum sw_exit_flags
{
    SW_EXIT_IN_COROUTINE = 1 << 1,
    SW_EXIT_IN_SERVER = 1 << 2
};

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_set, 0, 0, 1)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_create, 0, 0, 1)
    ZEND_ARG_CALLABLE_INFO(0, func, 0)
    ZEND_ARG_VARIADIC_INFO(0, params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_resume, 0, 0, 1)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_exists, 0, 0, 1)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getContext, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_exec, 0, 0, 1)
    ZEND_ARG_INFO(0, command)
    ZEND_ARG_INFO(0, get_error_stream)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_sleep, 0, 0, 1)
    ZEND_ARG_INFO(0, seconds)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_fread, 0, 0, 1)
    ZEND_ARG_INFO(0, handle)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_fgets, 0, 0, 1)
    ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_fwrite, 0, 0, 2)
    ZEND_ARG_INFO(0, handle)
    ZEND_ARG_INFO(0, string)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_gethostbyname, 0, 0, 1)
    ZEND_ARG_INFO(0, domain_name)
    ZEND_ARG_INFO(0, family)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_defer, 0, 0, 1)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getaddrinfo, 0, 0, 1)
    ZEND_ARG_INFO(0, hostname)
    ZEND_ARG_INFO(0, family)
    ZEND_ARG_INFO(0, socktype)
    ZEND_ARG_INFO(0, protocol)
    ZEND_ARG_INFO(0, service)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_readFile, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_writeFile, 0, 0, 2)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_statvfs, 0, 0, 1)
    ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getBackTrace, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
    ZEND_ARG_INFO(0, options)
    ZEND_ARG_INFO(0, limit)
ZEND_END_ARG_INFO()

bool PHPCoroutine::active = false;
uint64_t PHPCoroutine::max_num = SW_DEFAULT_MAX_CORO_NUM;
php_coro_task PHPCoroutine::main_task = {0};
bool PHPCoroutine::enable_preemptive_scheduler = false;
pthread_t PHPCoroutine::interrupt_thread_id;
bool PHPCoroutine::interrupt_thread_running = false;

static zend_bool* zend_vm_interrupt = nullptr;
static user_opcode_handler_t ori_exit_handler = NULL;
static unordered_map<long, Coroutine *> user_yield_coros;

static void (*orig_interrupt_function)(zend_execute_data *execute_data);
static void (*orig_error_function)(int type, const char *error_filename, const uint32_t error_lineno, const char *format, va_list args);

static zend_class_entry *swoole_coroutine_util_ce;
static zend_class_entry *swoole_exit_exception_ce;
static zend_object_handlers swoole_exit_exception_handlers;
static zend_class_entry *swoole_coroutine_iterator_ce;
static zend_class_entry *swoole_coroutine_context_ce;

static const zend_function_entry swoole_coroutine_util_methods[] =
{
    /**
     * Coroutine Scheduler
     */
    ZEND_FENTRY(create, ZEND_FN(swoole_coroutine_create), arginfo_swoole_coroutine_create, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(defer, ZEND_FN(swoole_coroutine_defer), arginfo_swoole_coroutine_defer, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_scheduler, set, arginfo_swoole_coroutine_set, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_scheduler, exists, arginfo_swoole_coroutine_exists, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_scheduler, yield, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_MALIAS(swoole_coroutine_scheduler, suspend, yield, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_scheduler, resume, arginfo_swoole_coroutine_resume, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_scheduler, stats, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_scheduler, getCid, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_MALIAS(swoole_coroutine_scheduler, getuid, getCid, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_scheduler, getPcid, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_scheduler, getContext, arginfo_swoole_coroutine_getContext, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_scheduler, getBackTrace, arginfo_swoole_coroutine_getBackTrace, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_scheduler, list, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_MALIAS(swoole_coroutine_scheduler, listCoroutines, list, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_scheduler, enableScheduler, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_scheduler, disableScheduler, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    /**
     * Coroutine System API
     */
    ZEND_FENTRY(exec, ZEND_FN(swoole_coroutine_exec), arginfo_swoole_coroutine_exec, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(gethostbyname, ZEND_FN(swoole_coroutine_gethostbyname), arginfo_swoole_coroutine_gethostbyname, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, sleep, arginfo_swoole_coroutine_sleep, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, fread, arginfo_swoole_coroutine_fread, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, fgets, arginfo_swoole_coroutine_fgets, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, fwrite, arginfo_swoole_coroutine_fwrite, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, readFile, arginfo_swoole_coroutine_readFile, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, writeFile, arginfo_swoole_coroutine_writeFile, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, getaddrinfo, arginfo_swoole_coroutine_getaddrinfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, statvfs, arginfo_swoole_coroutine_statvfs, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)

    PHP_FE_END
};

/**
 * Exit Exception
 */
static PHP_METHOD(swoole_exit_exception, getFlags);
static PHP_METHOD(swoole_exit_exception, getStatus);

static const zend_function_entry swoole_exit_exception_methods[] =
{
    PHP_ME(swoole_exit_exception, getFlags, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_exit_exception, getStatus, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static int coro_exit_handler(zend_execute_data *execute_data)
{
    zval ex;
    zend_object *obj;
    zend_long flags = 0;
    if (Coroutine::get_current())
    {
        flags |= SW_EXIT_IN_COROUTINE;
    }
    if (SwooleG.serv && SwooleG.serv->gs->start)
    {
        flags |= SW_EXIT_IN_SERVER;
    }
    if (flags)
    {
        const zend_op *opline = EX(opline);
        zval _exit_status;
        zval *exit_status = NULL;

        if (opline->op1_type != IS_UNUSED)
        {
            if (opline->op1_type == IS_CONST)
            {
                // see: https://github.com/php/php-src/commit/e70618aff6f447a298605d07648f2ce9e5a284f5
#ifdef EX_CONSTANT
                exit_status = EX_CONSTANT(opline->op1);
#else
                exit_status = RT_CONSTANT(opline, opline->op1);
#endif
            }
            else
            {
                exit_status = EX_VAR(opline->op1.var);
            }
            if (Z_ISREF_P(exit_status))
            {
                exit_status = Z_REFVAL_P(exit_status);
            }
            ZVAL_DUP(&_exit_status, exit_status);
            exit_status = &_exit_status;
        }
        else
        {
            exit_status = &_exit_status;
            ZVAL_NULL(exit_status);
        }
        obj = zend_throw_error_exception(swoole_exit_exception_ce, "swoole exit", 0, E_ERROR);
        ZVAL_OBJ(&ex, obj);
        zend_update_property_long(swoole_exit_exception_ce, &ex, ZEND_STRL("flags"), flags);
        Z_TRY_ADDREF_P(exit_status);
        zend_update_property(swoole_exit_exception_ce, &ex, ZEND_STRL("status"), exit_status);
    }

    return ZEND_USER_OPCODE_DISPATCH;
}

static void swoole_interrupt_resume(void *data)
{
    Coroutine *co = (Coroutine *) data;
    if (co && !co->is_end())
    {
        swTraceLog(SW_TRACE_COROUTINE, "interrupt_callback cid=%ld ", co->get_cid());
        co->resume();
    }
}

static void swoole_interrupt_function(zend_execute_data *execute_data)
{
    php_coro_task *task = PHPCoroutine::get_task();
    if (task && task->co && PHPCoroutine::is_schedulable(task))
    {
        SwooleG.main_reactor->defer(SwooleG.main_reactor, swoole_interrupt_resume, (void *) task->co);
        task->co->yield();
    }
    if (orig_interrupt_function)
    {
        orig_interrupt_function(execute_data);
    }
}

static void swoole_interrupt_thread_join(void *ptr)
{
    PHPCoroutine::interrupt_thread_stop();
}

void PHPCoroutine::init()
{
    Coroutine::set_on_yield(on_yield);
    Coroutine::set_on_resume(on_resume);
    Coroutine::set_on_close(on_close);
    orig_interrupt_function = zend_interrupt_function;
    zend_interrupt_function = swoole_interrupt_function;
}

inline void PHPCoroutine::activate()
{
    if (sw_unlikely(active))
    {
        return;
    }

    /* init reactor and register event wait */
    php_swoole_check_reactor();

    if (SWOOLE_G(enable_preemptive_scheduler))
    {
        /* create a thread to interrupt the coroutine that takes up too much time */
        interrupt_thread_start();
        swReactor_add_destroy_callback(SwooleG.main_reactor, swoole_interrupt_thread_join, nullptr);
    }

    if (zend_hash_str_find_ptr(&module_registry, ZEND_STRL("xdebug")))
    {
        php_swoole_fatal_error(E_WARNING, "Using Xdebug in coroutines is extremely dangerous, please notice that it may lead to coredump!");
    }

    /* replace the error function to save execute_data */
    orig_error_function = zend_error_cb;
    zend_error_cb = error;

    /* replace functions that can not work correctly in coroutine */
    inject_function();

    /* TODO: enable hook in v5.0.0 */
    // enable_hook(SW_HOOK_ALL);

    active = true;
}

void PHPCoroutine::error(int type, const char *error_filename, const uint32_t error_lineno, const char *format, va_list args)
{
    if (active && sw_unlikely(type & E_FATAL_ERRORS))
    {
        /* update the last coroutine's info */
        save_task(get_task());
    }
    if (sw_likely(orig_error_function))
    {
        orig_error_function(type, error_filename, error_lineno, format, args);
    }
}

void PHPCoroutine::shutdown()
{
    interrupt_thread_stop();
    Coroutine::bailout(nullptr);
}

void PHPCoroutine::interrupt_thread_stop()
{
    if (!interrupt_thread_running)
    {
        return;
    }
    interrupt_thread_running = false;
    if (pthread_join(interrupt_thread_id, NULL) < 0)
    {
        swSysWarn("pthread_join(%ld) failed", (ulong_t )interrupt_thread_id);
        interrupt_thread_running = true;
    }
}

void PHPCoroutine::interrupt_thread_start()
{
    if (interrupt_thread_running)
    {
        return;
    }
    zend_vm_interrupt = &EG(vm_interrupt);
    interrupt_thread_running = true;
    if (pthread_create(&interrupt_thread_id, NULL, (void * (*)(void *)) interrupt_thread_loop, NULL) < 0)
    {
        swSysError("pthread_create[PHPCoroutine Scheduler] failed");
        interrupt_thread_running = false;
    }
}

void PHPCoroutine::interrupt_thread_loop()
{
    static const useconds_t interval = (MAX_EXEC_MSEC / 2) * 1000;
    swSignal_none();
    while (interrupt_thread_running)
    {
        *zend_vm_interrupt = 1;
        usleep(interval);
    }
    pthread_exit(0);
}

inline void PHPCoroutine::vm_stack_init(void)
{
    uint32_t size = SW_DEFAULT_PHP_STACK_PAGE_SIZE;
    zend_vm_stack page = (zend_vm_stack) emalloc(size);

    page->top = ZEND_VM_STACK_ELEMENTS(page);
    page->end = (zval*) ((char*) page + size);
    page->prev = NULL;

    EG(vm_stack) = page;
    EG(vm_stack)->top++;
    EG(vm_stack_top) = EG(vm_stack)->top;
    EG(vm_stack_end) = EG(vm_stack)->end;
#if PHP_VERSION_ID >= 70300
    EG(vm_stack_page_size) = size;
#endif
}

inline void PHPCoroutine::vm_stack_destroy(void)
{
    zend_vm_stack stack = EG(vm_stack);

    while (stack != NULL)
    {
        zend_vm_stack p = stack->prev;
        efree(stack);
        stack = p;
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
inline void PHPCoroutine::save_vm_stack(php_coro_task *task)
{
#ifdef SW_CORO_SWAP_BAILOUT
    task->bailout = EG(bailout);
#endif
    task->vm_stack_top = EG(vm_stack_top);
    task->vm_stack_end = EG(vm_stack_end);
    task->vm_stack = EG(vm_stack);
#if PHP_VERSION_ID >= 70300
    task->vm_stack_page_size = EG(vm_stack_page_size);
#endif
    task->execute_data = EG(current_execute_data);
    task->error_handling = EG(error_handling);
    task->exception_class = EG(exception_class);
    task->exception = EG(exception);
}

inline void PHPCoroutine::restore_vm_stack(php_coro_task *task)
{
#ifdef SW_CORO_SWAP_BAILOUT
    EG(bailout) = task->bailout;
#endif
    EG(vm_stack_top) = task->vm_stack_top;
    EG(vm_stack_end) = task->vm_stack_end;
    EG(vm_stack) = task->vm_stack;
#if PHP_VERSION_ID >= 70300
    EG(vm_stack_page_size) = task->vm_stack_page_size;
#endif
    EG(current_execute_data) = task->execute_data;
    EG(error_handling) = task->error_handling;
    EG(exception_class) = task->exception_class;
    EG(exception) = task->exception;
}

inline void PHPCoroutine::save_og(php_coro_task *task)
{
    if (OG(handlers).elements)
    {
        task->output_ptr = (zend_output_globals *) emalloc(sizeof(zend_output_globals));
        memcpy(task->output_ptr, SWOG, sizeof(zend_output_globals));
        php_output_activate();
    }
    else
    {
        task->output_ptr = NULL;
    }
}

inline void PHPCoroutine::restore_og(php_coro_task *task)
{
    if (task->output_ptr)
    {
        memcpy(SWOG, task->output_ptr, sizeof(zend_output_globals));
        efree(task->output_ptr);
        task->output_ptr = NULL;
    }
}

void PHPCoroutine::save_task(php_coro_task *task)
{
    save_vm_stack(task);
    save_og(task);
}

void PHPCoroutine::restore_task(php_coro_task *task)
{
    restore_vm_stack(task);
    restore_og(task);
}

void PHPCoroutine::on_yield(void *arg)
{
    php_coro_task *task = (php_coro_task *) arg;
    php_coro_task *origin_task = get_origin_task(task);
    swTraceLog(SW_TRACE_COROUTINE,"php_coro_yield from cid=%ld to cid=%ld", task->co->get_cid(), task->co->get_origin_cid());
    save_task(task);
    restore_task(origin_task);
}

void PHPCoroutine::on_resume(void *arg)
{
    php_coro_task *task = (php_coro_task *) arg;
    php_coro_task *current_task = get_task();
    save_task(current_task);
    restore_task(task);
    record_last_msec(task);
    swTraceLog(SW_TRACE_COROUTINE,"php_coro_resume from cid=%ld to cid=%ld", Coroutine::get_current_cid(), task->co->get_cid());
}

void PHPCoroutine::on_close(void *arg)
{
    php_coro_task *task = (php_coro_task *) arg;
    php_coro_task *origin_task = get_origin_task(task);
#ifdef SW_LOG_TRACE_OPEN
    long cid = task->co->get_cid();
    long origin_cid = task->co->get_origin_cid();
#endif

    if (SwooleG.hooks[SW_GLOBAL_HOOK_ON_CORO_STOP])
    {
        swoole_call_hook(SW_GLOBAL_HOOK_ON_CORO_STOP, task);
    }

    if (OG(handlers).elements)
    {
        if (OG(active))
        {
            php_output_end_all();
        }
        php_output_deactivate();
        php_output_activate();
    }
    vm_stack_destroy();
    restore_task(origin_task);

    swTraceLog(
        SW_TRACE_COROUTINE, "coro close cid=%ld and resume to %ld, %zu remained. usage size: %zu. malloc size: %zu",
        cid, origin_cid, (uintmax_t) Coroutine::count() - 1, (uintmax_t) zend_memory_usage(0), (uintmax_t) zend_memory_usage(1)
    );
}

void PHPCoroutine::main_func(void *arg)
{
#ifdef SW_CORO_SUPPORT_BAILOUT
    zend_first_try {
#endif
    int i;
    php_coro_args *php_arg = (php_coro_args *) arg;
    zend_fcall_info_cache fci_cache = *php_arg->fci_cache;
    zend_function *func = fci_cache.function_handler;
    zval *argv = php_arg->argv;
    int argc = php_arg->argc;
    php_coro_task *task;
    zend_execute_data *call;
    zval _retval, *retval = &_retval;

    if (fci_cache.object)
    {
        GC_ADDREF(fci_cache.object);
    }

    vm_stack_init();
    call = (zend_execute_data *) (EG(vm_stack_top));
    task = (php_coro_task *) EG(vm_stack_top);
    EG(vm_stack_top) = (zval *) ((char *) call + PHP_CORO_TASK_SLOT * sizeof(zval));

#if PHP_VERSION_ID < 70400
    call = zend_vm_stack_push_call_frame(
        ZEND_CALL_TOP_FUNCTION | ZEND_CALL_ALLOCATED,
        func, argc, fci_cache.called_scope, fci_cache.object
    );
#else
    do {
        uint32_t call_info;
        void *object_or_called_scope;
        if ((func->common.fn_flags & ZEND_ACC_STATIC) || !fci_cache.object) {
            object_or_called_scope = fci_cache.called_scope;
            call_info = ZEND_CALL_TOP_FUNCTION | ZEND_CALL_DYNAMIC;
        } else {
            object_or_called_scope = fci_cache.object;
            call_info = ZEND_CALL_TOP_FUNCTION | ZEND_CALL_DYNAMIC | ZEND_CALL_HAS_THIS;
        }
        call = zend_vm_stack_push_call_frame(call_info, func, argc, object_or_called_scope);
    } while (0);
#endif

    for (i = 0; i < argc; ++i)
    {
        zval *param;
        zval *arg = &argv[i];
        if (Z_ISREF_P(arg) && !(func->common.fn_flags & ZEND_ACC_CALL_VIA_TRAMPOLINE))
        {
            /* don't separate references for __call */
            arg = Z_REFVAL_P(arg);
        }
        param = ZEND_CALL_ARG(call, i + 1);
        ZVAL_COPY(param, arg);
    }

    call->symbol_table = NULL;

    if (func->op_array.fn_flags & ZEND_ACC_CLOSURE)
    {
        uint32_t call_info;
        GC_ADDREF(ZEND_CLOSURE_OBJECT(func));
        call_info = ZEND_CALL_CLOSURE;
        ZEND_ADD_CALL_FLAG(call, call_info);
    }

#if defined(SW_CORO_SWAP_BAILOUT) && !defined(SW_CORO_SUPPORT_BAILOUT)
    EG(bailout) = NULL;
#endif
    EG(current_execute_data) = call;
    EG(error_handling) = EH_NORMAL;
    EG(exception_class) = NULL;
    EG(exception) = NULL;

    save_vm_stack(task);
    record_last_msec(task);

    task->output_ptr = NULL;
    task->co = Coroutine::get_current();
    task->co->set_task((void *) task);
    task->defer_tasks = nullptr;
    task->pcid = task->co->get_origin_cid();
    task->context = nullptr;
    task->enable_scheduler = 1;

    swTraceLog(
        SW_TRACE_COROUTINE, "Create coro id: %ld, origin cid: %ld, coro total count: %zu, heap size: %zu",
        task->co->get_cid(), task->co->get_origin_cid(), (uintmax_t) Coroutine::count(), (uintmax_t) zend_memory_usage(0)
    );

    if (SwooleG.hooks[SW_GLOBAL_HOOK_ON_CORO_START])
    {
        swoole_call_hook(SW_GLOBAL_HOOK_ON_CORO_START, task);
    }

    if (EXPECTED(func->type == ZEND_USER_FUNCTION))
    {
        ZVAL_UNDEF(retval);
        // TODO: enhancement it, separate execute data is necessary, but we lose the backtrace
        EG(current_execute_data) = NULL;
#if PHP_VERSION_ID >= 70200
        zend_init_func_execute_data(call, &func->op_array, retval);
#else
        zend_init_execute_data(call, &func->op_array, retval);
#endif
        zend_execute_ex(EG(current_execute_data));
    }
    else /* ZEND_INTERNAL_FUNCTION */
    {
        ZVAL_NULL(retval);
        call->prev_execute_data = NULL;
        call->return_value = NULL; /* this is not a constructor call */
        execute_internal(call, retval);
        zend_vm_stack_free_args(call);
    }

    if (task->defer_tasks)
    {
        std::stack<php_swoole_fci *> *tasks = task->defer_tasks;
        while (!tasks->empty())
        {
            php_swoole_fci *defer_fci = tasks->top();
            tasks->pop();
            defer_fci->fci.param_count = 1;
            defer_fci->fci.params = retval;
            if (UNEXPECTED(sw_zend_call_function_anyway(&defer_fci->fci, &defer_fci->fci_cache) != SUCCESS))
            {
                php_swoole_fatal_error(E_WARNING, "defer callback handler error");
            }
            sw_zend_fci_cache_discard(&defer_fci->fci_cache);
            efree(defer_fci);
        }
        delete task->defer_tasks;
        task->defer_tasks = nullptr;
    }

    // resources release
    zval_ptr_dtor(retval);
    if (fci_cache.object)
    {
        OBJ_RELEASE(fci_cache.object);
    }
    if (task->context)
    {
        OBJ_RELEASE(task->context);
    }

    // TODO: exceptions will only cause the coroutine to exit
    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }

#ifdef SW_CORO_SUPPORT_BAILOUT
    } zend_catch {
        Coroutine::bailout([](){ sw_zend_bailout(); });
    } zend_end_try();
#endif
}

long PHPCoroutine::create(zend_fcall_info_cache *fci_cache, uint32_t argc, zval *argv)
{
    if (sw_unlikely(Coroutine::count() >= max_num))
    {
        php_swoole_fatal_error(E_WARNING, "exceed max number of coroutine %zu", (uintmax_t) Coroutine::count());
        return SW_CORO_ERR_LIMIT;
    }
    if (sw_unlikely(!fci_cache || !fci_cache->function_handler))
    {
        php_swoole_fatal_error(E_ERROR, "invalid function call info cache");
        return SW_CORO_ERR_INVALID;
    }
    zend_uchar type = fci_cache->function_handler->type;
    if (sw_unlikely(type != ZEND_USER_FUNCTION && type != ZEND_INTERNAL_FUNCTION))
    {
        php_swoole_fatal_error(E_ERROR, "invalid function type %u", fci_cache->function_handler->type);
        return SW_CORO_ERR_INVALID;
    }

    if (sw_unlikely(!active))
    {
        activate();
    }

    php_coro_args php_coro_args;
    php_coro_args.fci_cache = fci_cache;
    php_coro_args.argv = argv;
    php_coro_args.argc = argc;
    save_task(get_task());

    return Coroutine::create(main_func, (void*) &php_coro_args);
}

void PHPCoroutine::defer(php_swoole_fci *fci)
{
    php_coro_task *task = get_task();
    if (task->defer_tasks == nullptr)
    {
        task->defer_tasks = new std::stack<php_swoole_fci *>;
    }
    task->defer_tasks->push(fci);
}

void PHPCoroutine::yield_m(zval *return_value, php_coro_context *sw_current_context)
{
    Coroutine::get_current_safe();
    php_coro_task *task = get_task();
    sw_current_context->current_coro_return_value_ptr = return_value;
    sw_current_context->current_task = task;
    on_yield(task);
    task->co->yield_naked();
}

int PHPCoroutine::resume_m(php_coro_context *sw_current_context, zval *retval, zval *coro_retval)
{
    php_coro_task *task = sw_current_context->current_task;
    on_resume(task);
    if (retval)
    {
        ZVAL_COPY(sw_current_context->current_coro_return_value_ptr, retval);
    }
    task->co->resume_naked();
    return SW_CORO_ERR_END;
}

void swoole_coroutine_init(int module_number)
{
    PHPCoroutine::init();

    SW_INIT_CLASS_ENTRY_BASE(swoole_coroutine_util, "Swoole\\Coroutine", NULL, "Co", swoole_coroutine_util_methods, NULL);
    SW_SET_CLASS_CREATE(swoole_coroutine_util, sw_zend_create_object_deny);

    SW_INIT_CLASS_ENTRY_BASE(swoole_coroutine_iterator, "Swoole\\Coroutine\\Iterator", NULL, "Co\\Iterator", NULL, spl_ce_ArrayIterator);
    SW_INIT_CLASS_ENTRY_BASE(swoole_coroutine_context, "Swoole\\Coroutine\\Context", NULL, "Co\\Context", NULL, spl_ce_ArrayObject);

    swoole_coroutine_scheduler_init(module_number);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_DEFAULT_MAX_CORO_NUM", SW_DEFAULT_MAX_CORO_NUM);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_MAX_NUM_LIMIT", SW_CORO_MAX_NUM_LIMIT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_INIT", SW_CORO_INIT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_WAITING", SW_CORO_WAITING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_RUNNING", SW_CORO_RUNNING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_END", SW_CORO_END);

    //prohibit exit in coroutine
    SW_INIT_CLASS_ENTRY_EX(swoole_exit_exception, "Swoole\\ExitException", NULL, NULL, swoole_exit_exception_methods, swoole_exception);
    zend_declare_property_long(swoole_exit_exception_ce, ZEND_STRL("flags"), 0, ZEND_ACC_PRIVATE);
    zend_declare_property_long(swoole_exit_exception_ce, ZEND_STRL("status"), 0, ZEND_ACC_PRIVATE);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_EXIT_IN_COROUTINE", SW_EXIT_IN_COROUTINE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_EXIT_IN_SERVER", SW_EXIT_IN_SERVER);

    if (SWOOLE_G(cli))
    {
        ori_exit_handler = zend_get_user_opcode_handler(ZEND_EXIT);
        zend_set_user_opcode_handler(ZEND_EXIT, coro_exit_handler);
    }
}

void swoole_coroutine_rshutdown()
{
    PHPCoroutine::shutdown();
}

static PHP_METHOD(swoole_exit_exception, getFlags)
{
    SW_RETURN_PROPERTY("flags");
}

static PHP_METHOD(swoole_exit_exception, getStatus)
{
    SW_RETURN_PROPERTY("status");
}

PHP_FUNCTION(swoole_coroutine_create)
{
    zend_fcall_info fci = empty_fcall_info;
    zend_fcall_info_cache fci_cache = empty_fcall_info_cache;

    ZEND_PARSE_PARAMETERS_START(1, -1)
        Z_PARAM_FUNC(fci, fci_cache)
        Z_PARAM_VARIADIC('*', fci.params, fci.param_count)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (sw_unlikely(SWOOLE_G(req_status) == PHP_SWOOLE_CALL_USER_SHUTDOWNFUNC_BEGIN))
    {
        zend_function *func = (zend_function *) EG(current_execute_data)->prev_execute_data->func;
        if (func->common.function_name && sw_unlikely(memcmp(ZSTR_VAL(func->common.function_name), ZEND_STRS("__destruct")) == 0))
        {
            php_swoole_fatal_error(E_ERROR, "can not use coroutine in __destruct after php_request_shutdown");
            RETURN_FALSE;
        }
    }

    long cid = PHPCoroutine::create(&fci_cache, fci.param_count, fci.params);
    if (sw_likely(cid > 0))
    {
        RETURN_LONG(cid);
    }
    else
    {
        RETURN_FALSE;
    }
}

PHP_FUNCTION(swoole_coroutine_defer)
{
    zend_fcall_info fci = empty_fcall_info;
    zend_fcall_info_cache fci_cache = empty_fcall_info_cache;
    php_swoole_fci *defer_fci;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_FUNC(fci, fci_cache)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Coroutine::get_current_safe();
    defer_fci = (php_swoole_fci *) emalloc(sizeof(php_swoole_fci));
    defer_fci->fci = fci;
    defer_fci->fci_cache = fci_cache;
    sw_zend_fci_cache_persist(&defer_fci->fci_cache);
    PHPCoroutine::defer(defer_fci);
}

PHP_METHOD(swoole_coroutine_scheduler, stats)
{
    array_init(return_value);
    if (SwooleG.main_reactor)
    {
        add_assoc_long_ex(return_value, ZEND_STRL("event_num"), SwooleG.main_reactor->event_num);
        add_assoc_long_ex(return_value, ZEND_STRL("signal_listener_num"), SwooleG.main_reactor->signal_listener_num);
    }
    add_assoc_long_ex(return_value, ZEND_STRL("aio_task_num"), SwooleAIO.task_num);
    add_assoc_long_ex(return_value, ZEND_STRL("c_stack_size"), Coroutine::get_stack_size());
    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_num"), Coroutine::count());
    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_peak_num"), Coroutine::get_peak_num());
    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_last_cid"), Coroutine::get_last_cid());
}

PHP_METHOD(swoole_coroutine_scheduler, getCid)
{
    RETURN_LONG(PHPCoroutine::get_cid());
}

PHP_METHOD(swoole_coroutine_scheduler, getPcid)
{
    RETURN_LONG(PHPCoroutine::get_pcid());
}

PHP_METHOD(swoole_coroutine_scheduler, getContext)
{
    zend_long cid = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(cid)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    php_coro_task *task = (php_coro_task *) (EXPECTED(cid == 0) ? Coroutine::get_current_task() : Coroutine::get_task_by_cid(cid));
    if (UNEXPECTED(!task))
    {
        RETURN_NULL();
    }
    if (UNEXPECTED(!task->context))
    {
        object_init_ex(return_value, swoole_coroutine_context_ce);
        task->context = Z_OBJ_P(return_value);
    }
    GC_ADDREF(task->context);
    RETURN_OBJ(task->context);
}

PHP_METHOD(swoole_coroutine_scheduler, exists)
{
    zend_long cid;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(cid)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(Coroutine::get_by_cid(cid) != nullptr);
}

PHP_METHOD(swoole_coroutine_scheduler, resume)
{
    long cid;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &cid) == FAILURE)
    {
        RETURN_FALSE;
    }

    auto coroutine_iterator = user_yield_coros.find(cid);
    if (coroutine_iterator == user_yield_coros.end())
    {
        php_swoole_fatal_error(E_WARNING, "you can not resume the coroutine which is in IO operation or non-existent");
        RETURN_FALSE;
    }

    Coroutine* co = coroutine_iterator->second;
    user_yield_coros.erase(cid);
    co->resume();
    RETURN_TRUE;
}

PHP_METHOD(swoole_coroutine_scheduler, yield)
{
    Coroutine* co = Coroutine::get_current_safe();
    user_yield_coros[co->get_cid()] = co;
    co->yield();
    RETURN_TRUE;
}

PHP_METHOD(swoole_coroutine_scheduler, getBackTrace)
{
    zend_long cid = 0;
    zend_long options = DEBUG_BACKTRACE_PROVIDE_OBJECT;
    zend_long limit = 0;

    ZEND_PARSE_PARAMETERS_START(0, 3)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(cid)
        Z_PARAM_LONG(options)
        Z_PARAM_LONG(limit)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (!cid || cid == PHPCoroutine::get_cid())
    {
        zend_fetch_debug_backtrace(return_value, 0, options, limit);
    }
    else
    {
        php_coro_task *task = (php_coro_task *) PHPCoroutine::get_task_by_cid(cid);
        if (UNEXPECTED(!task))
        {
            RETURN_FALSE;
        }
        zend_execute_data *ex_backup = EG(current_execute_data);
        EG(current_execute_data) = task->execute_data;
        zend_fetch_debug_backtrace(return_value, 0, options, limit);
        EG(current_execute_data) = ex_backup;
    }
}

PHP_METHOD(swoole_coroutine_scheduler, list)
{
    zval zlist;
    array_init(&zlist);
    for (auto &co : Coroutine::coroutines) {
        add_next_index_long(&zlist, co.second->get_cid());
    }
    object_init_ex(return_value, swoole_coroutine_iterator_ce);
    sw_zend_call_method_with_1_params(
        return_value,
        swoole_coroutine_iterator_ce,
        &swoole_coroutine_iterator_ce->constructor,
        (const char *) "__construct",
        NULL,
        &zlist
    );
    zval_ptr_dtor(&zlist);
}

PHP_METHOD(swoole_coroutine_scheduler, enableScheduler)
{
    RETURN_BOOL(PHPCoroutine::enable_scheduler());
}

PHP_METHOD(swoole_coroutine_scheduler, disableScheduler)
{
    RETURN_BOOL(PHPCoroutine::disable_scheduler());
}
