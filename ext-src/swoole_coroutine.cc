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
#include "php_swoole_thread.h"
#include "php_swoole_coroutine_system.h"

#include "swoole_server.h"
#include "swoole_signal.h"

#include "zend_builtin_functions.h"
#include "ext/spl/spl_array.h"

#ifdef SWOOLE_COROUTINE_MOCK_FIBER_CONTEXT
#include "zend_observer.h"
#endif

#include <unordered_map>
#include <chrono>

BEGIN_EXTERN_C()
#include "stubs/php_swoole_coroutine_arginfo.h"
END_EXTERN_C()

using std::unordered_map;
using swoole::Coroutine;
using swoole::PHPContext;
using swoole::PHPCoroutine;
using swoole::coroutine::Socket;
using swoole::coroutine::System;

#if PHP_VERSION_ID < 80100
static zend_always_inline zend_vm_stack zend_vm_stack_new_page(size_t size, zend_vm_stack prev) {
    zend_vm_stack page = (zend_vm_stack) emalloc(size);

    page->top = ZEND_VM_STACK_ELEMENTS(page);
    page->end = (zval *) ((char *) page + size);
    page->prev = prev;
    return page;
}
#endif

enum sw_exit_flags { SW_EXIT_IN_COROUTINE = 1 << 1, SW_EXIT_IN_SERVER = 1 << 2 };

SW_THREAD_LOCAL bool PHPCoroutine::activated = false;
SW_THREAD_LOCAL zend_array *PHPCoroutine::options = nullptr;

SW_THREAD_LOCAL PHPCoroutine::Config PHPCoroutine::config{
    SW_DEFAULT_MAX_CORO_NUM,
    0,
    false,
    true,
};

SW_THREAD_LOCAL PHPContext PHPCoroutine::main_context{};
SW_THREAD_LOCAL std::thread PHPCoroutine::interrupt_thread;
SW_THREAD_LOCAL bool PHPCoroutine::interrupt_thread_running = false;

extern void php_swoole_load_library();

static zend_atomic_bool *zend_vm_interrupt = nullptr;
#if PHP_VERSION_ID < 80400
static user_opcode_handler_t ori_exit_handler = nullptr;
#endif
static user_opcode_handler_t ori_begin_silence_handler = nullptr;
static user_opcode_handler_t ori_end_silence_handler = nullptr;
static unordered_map<long, Coroutine *> user_yield_coros;

static void (*orig_interrupt_function)(zend_execute_data *execute_data) = nullptr;

static zend_class_entry *swoole_coroutine_util_ce;
static zend_class_entry *swoole_exit_exception_ce;
static zend_object_handlers swoole_exit_exception_handlers;
static zend_class_entry *swoole_coroutine_iterator_ce;
static zend_class_entry *swoole_coroutine_context_ce;

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_coroutine, exists);
static PHP_METHOD(swoole_coroutine, yield);
static PHP_METHOD(swoole_coroutine, resume);
static PHP_METHOD(swoole_coroutine, join);
static PHP_METHOD(swoole_coroutine, cancel);
static PHP_METHOD(swoole_coroutine, isCanceled);
static PHP_METHOD(swoole_coroutine, stats);
static PHP_METHOD(swoole_coroutine, getCid);
static PHP_METHOD(swoole_coroutine, getPcid);
static PHP_METHOD(swoole_coroutine, getContext);
static PHP_METHOD(swoole_coroutine, getBackTrace);
static PHP_METHOD(swoole_coroutine, printBackTrace);
static PHP_METHOD(swoole_coroutine, getElapsed);
static PHP_METHOD(swoole_coroutine, getStackUsage);
static PHP_METHOD(swoole_coroutine, list);
static PHP_METHOD(swoole_coroutine, enableScheduler);
static PHP_METHOD(swoole_coroutine, disableScheduler);
#ifdef SW_CORO_TIME
static PHP_METHOD(swoole_coroutine, getExecuteTime);
#endif
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_coroutine_methods[] =
{
    /**
     * Coroutine Core API
     */
    ZEND_FENTRY(create, ZEND_FN(swoole_coroutine_create), arginfo_class_Swoole_Coroutine_create,           ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(defer, ZEND_FN(swoole_coroutine_defer),   arginfo_class_Swoole_Coroutine_defer,            ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_scheduler, set,               arginfo_class_Swoole_Coroutine_set,              ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_scheduler, getOptions,        arginfo_class_Swoole_Coroutine_getOptions,       ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, exists,                      arginfo_class_Swoole_Coroutine_exists,           ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, yield,                       arginfo_class_Swoole_Coroutine_yield,            ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, cancel,                      arginfo_class_Swoole_Coroutine_cancel,           ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, join,                        arginfo_class_Swoole_Coroutine_join,             ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, isCanceled,                  arginfo_class_Swoole_Coroutine_isCanceled,       ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_MALIAS(swoole_coroutine, suspend, yield,          arginfo_class_Swoole_Coroutine_suspend,          ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, resume,                      arginfo_class_Swoole_Coroutine_resume,           ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, stats,                       arginfo_class_Swoole_Coroutine_stats,            ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, getCid,                      arginfo_class_Swoole_Coroutine_getCid,           ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_MALIAS(swoole_coroutine, getuid, getCid,          arginfo_class_Swoole_Coroutine_getuid,           ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, getPcid,                     arginfo_class_Swoole_Coroutine_getPcid,          ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, getContext,                  arginfo_class_Swoole_Coroutine_getContext,       ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, getBackTrace,                arginfo_class_Swoole_Coroutine_getBackTrace,     ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, printBackTrace,              arginfo_class_Swoole_Coroutine_printBackTrace,   ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, getElapsed,                  arginfo_class_Swoole_Coroutine_getElapsed,       ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, getStackUsage,               arginfo_class_Swoole_Coroutine_getStackUsage,    ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, list,                        arginfo_class_Swoole_Coroutine_list,             ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_MALIAS(swoole_coroutine, listCoroutines, list,    arginfo_class_Swoole_Coroutine_listCoroutines,   ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, enableScheduler,             arginfo_class_Swoole_Coroutine_enableScheduler,  ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, disableScheduler,            arginfo_class_Swoole_Coroutine_disableScheduler, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
#ifdef SW_CORO_TIME
    PHP_ME(swoole_coroutine, getExecuteTime,              arginfo_class_Swoole_Coroutine_getExecuteTime,   ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
#endif
    /**
     * Coroutine System API
     */
    ZEND_FENTRY(gethostbyname,      ZEND_FN(swoole_coroutine_gethostbyname), arginfo_class_Swoole_Coroutine_System_gethostbyname, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(dnsLookup,          ZEND_FN(swoole_async_dns_lookup_coro),   arginfo_class_Swoole_Coroutine_System_dnsLookup,     ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, exec,                                    arginfo_class_Swoole_Coroutine_System_exec,          ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, sleep,                                   arginfo_class_Swoole_Coroutine_System_sleep,         ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, getaddrinfo,                             arginfo_class_Swoole_Coroutine_System_getaddrinfo,   ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, statvfs,                                 arginfo_class_Swoole_Coroutine_System_statvfs,       ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, readFile,                                arginfo_class_Swoole_Coroutine_System_readFile,      ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, writeFile,                               arginfo_class_Swoole_Coroutine_System_writeFile,     ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, wait,                                    arginfo_class_Swoole_Coroutine_System_wait,          ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, waitPid,                                 arginfo_class_Swoole_Coroutine_System_waitPid,       ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, waitSignal,                              arginfo_class_Swoole_Coroutine_System_waitSignal,    ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, waitEvent,                               arginfo_class_Swoole_Coroutine_System_waitEvent,     ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};
// clang-format on

/**
 * Exit Exception
 */
static PHP_METHOD(swoole_exit_exception, getFlags);
static PHP_METHOD(swoole_exit_exception, getStatus);

// clang-format off
static const zend_function_entry swoole_exit_exception_methods[] = {
    PHP_ME(swoole_exit_exception, getFlags,  arginfo_class_Swoole_ExitException_getFlags,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_exit_exception, getStatus, arginfo_class_Swoole_ExitException_getStatus, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

#if PHP_VERSION_ID < 80400
static int coro_exit_handler(zend_execute_data *execute_data) {
    zval ex;
    zend_object *obj;
    zend_long flags = 0;
    if (Coroutine::get_current()) {
        flags |= SW_EXIT_IN_COROUTINE;
    }
    if (sw_server() && sw_server()->is_started()) {
        flags |= SW_EXIT_IN_SERVER;
    }
    if (flags) {
        const zend_op *opline = EX(opline);
        zval _exit_status{};
        zval *exit_status = nullptr;

        if (opline->op1_type != IS_UNUSED) {
            if (opline->op1_type == IS_CONST) {
                // see: https://github.com/php/php-src/commit/e70618aff6f447a298605d07648f2ce9e5a284f5
#ifdef EX_CONSTANT
                exit_status = EX_CONSTANT(opline->op1);
#else
                exit_status = RT_CONSTANT(opline, opline->op1);
#endif
            } else {
                exit_status = EX_VAR(opline->op1.var);
            }
            if (Z_ISREF_P(exit_status)) {
                exit_status = Z_REFVAL_P(exit_status);
            }
            ZVAL_DUP(&_exit_status, exit_status);
            exit_status = &_exit_status;
        } else {
            exit_status = &_exit_status;
            ZVAL_NULL(exit_status);
        }
        obj = zend_throw_exception(swoole_exit_exception_ce, "swoole exit", 0);
        ZVAL_OBJ(&ex, obj);
        zend_update_property_long(swoole_exit_exception_ce, SW_Z8_OBJ_P(&ex), ZEND_STRL("flags"), flags);
        Z_TRY_ADDREF_P(exit_status);
        zend_update_property(swoole_exit_exception_ce, SW_Z8_OBJ_P(&ex), ZEND_STRL("status"), exit_status);
    }

    return ZEND_USER_OPCODE_DISPATCH;
}
#else
SW_EXTERN_C_BEGIN
PHP_FUNCTION(swoole_exit) {
    zend_long flags = 0;
    if (Coroutine::get_current()) {
        flags |= SW_EXIT_IN_COROUTINE;
    }

    if (sw_server() && sw_server()->is_started()) {
        flags |= SW_EXIT_IN_SERVER;
    }

    zend_string *message = NULL;
    zend_long status = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_STR_OR_LONG(message, status)
    ZEND_PARSE_PARAMETERS_END();

    if (flags) {
        zval ex = {};
        zend_object *obj =
            zend_throw_exception(swoole_exit_exception_ce, (message ? ZSTR_VAL(message) : "swoole exit"), 0);
        ZVAL_OBJ(&ex, obj);
        zend_update_property_long(swoole_exit_exception_ce, SW_Z8_OBJ_P(&ex), ZEND_STRL("flags"), flags);
        if (message) {
            zend_update_property_str(swoole_exit_exception_ce, SW_Z8_OBJ_P(&ex), ZEND_STRL("status"), message);
        } else {
            zend_update_property_long(swoole_exit_exception_ce, SW_Z8_OBJ_P(&ex), ZEND_STRL("status"), status);
        }
    } else {
        if (!php_swoole_call_original_handler(ZEND_STRL("exit"), INTERNAL_FUNCTION_PARAM_PASSTHRU)) {
            if (message) {
                php_write(ZSTR_VAL(message), ZSTR_LEN(message));
            }
            sw_php_exit(status);
        }
    }
}
SW_EXTERN_C_END
#endif

static int coro_begin_silence_handler(zend_execute_data *execute_data) {
    PHPContext *task = PHPCoroutine::get_context();
    task->in_silence = true;
    task->ori_error_reporting = EG(error_reporting);
    return ZEND_USER_OPCODE_DISPATCH;
}

static int coro_end_silence_handler(zend_execute_data *execute_data) {
    PHPContext *task = PHPCoroutine::get_context();
    task->in_silence = false;
    return ZEND_USER_OPCODE_DISPATCH;
}

static void coro_interrupt_resume(void *data) {
    Coroutine *co = (Coroutine *) data;
    if (co && !co->is_end()) {
        swoole_trace_log(SW_TRACE_COROUTINE, "interrupt_callback cid=%ld ", co->get_cid());
        co->resume();
    }
}

static void coro_interrupt_function(zend_execute_data *execute_data) {
    PHPContext *task = PHPCoroutine::get_context();
    if (task && task->co && PHPCoroutine::is_schedulable(task)) {
        swoole_event_defer(coro_interrupt_resume, (void *) task->co);
        task->co->yield();
    }
    if (orig_interrupt_function) {
        orig_interrupt_function(execute_data);
    }
}

PHPContext *PHPCoroutine::create_context(Args *args) {
    PHPContext *ctx = (PHPContext *) emalloc(sizeof(PHPContext));
    ctx->output_ptr = nullptr;
#if PHP_VERSION_ID < 80100
    ctx->array_walk_fci = nullptr;
#endif
    ctx->in_silence = false;

    ctx->co = Coroutine::get_current();
    ctx->co->set_task((void *) ctx);
    ctx->defer_tasks = nullptr;
    ctx->pcid = ctx->co->get_origin_cid();
    ctx->context = nullptr;
    ctx->on_yield = nullptr;
    ctx->on_resume = nullptr;
    ctx->on_close = nullptr;
    ctx->enable_scheduler = true;

#ifdef SWOOLE_COROUTINE_MOCK_FIBER_CONTEXT
    fiber_context_try_init(ctx);
    ctx->fiber_init_notified = false;
#endif

    EG(vm_stack) = zend_vm_stack_new_page(SW_DEFAULT_PHP_STACK_PAGE_SIZE, nullptr);
    EG(vm_stack_top) = EG(vm_stack)->top + ZEND_CALL_FRAME_SLOT;
    EG(vm_stack_end) = EG(vm_stack)->end;
    EG(vm_stack_page_size) = SW_DEFAULT_PHP_STACK_PAGE_SIZE;

    zend_function *func = EG(current_execute_data)->func;
    zend_execute_data *call = (zend_execute_data *) (EG(vm_stack_top));
    EG(current_execute_data) = call;
    memset(EG(current_execute_data), 0, sizeof(zend_execute_data));

    EG(error_handling) = EH_NORMAL;
    EG(exception_class) = nullptr;
    EG(exception) = nullptr;
    EG(jit_trace_num) = 0;

    call->func = func;
    EG(vm_stack_top) += ZEND_CALL_FRAME_SLOT;

#ifdef ZEND_CHECK_STACK_LIMIT
    EG(stack_base) = stack_base(ctx);
    EG(stack_limit) = stack_limit(ctx);
#endif

    save_vm_stack(ctx);
    record_last_msec(ctx);

    ctx->fci_cache = *args->fci_cache;
    ctx->fci.size = sizeof(ctx->fci);
    ctx->fci.object = NULL;
    ctx->fci.param_count = args->argc;
    ctx->fci.params = args->argv;
    ctx->fci.named_params = NULL;
    ctx->return_value = {};
    ctx->fci.retval = &ctx->return_value;

    if (args->callable) {
        ctx->fci.function_name = *args->callable;
        Z_TRY_ADDREF(ctx->fci.function_name);
    } else {
        ZVAL_UNDEF(&ctx->fci.function_name);
    }
    sw_zend_fci_cache_persist(&ctx->fci_cache);

    return ctx;
}

void PHPCoroutine::bailout() {
    Coroutine::bailout([]() {
        if (sw_reactor()) {
            sw_reactor()->running = false;
            sw_reactor()->bailout = true;
        }
        zend_bailout();
    });
}

bool PHPCoroutine::catch_exception() {
    if (UNEXPECTED(EG(exception))) {
        // the exception error messages MUST be output on the current coroutine stack
        zend_exception_error(EG(exception), E_ERROR);
        return true;
    }
    return false;
}

void PHPCoroutine::activate() {
    if (sw_unlikely(activated)) {
        return;
    }

    zval *enable_library = zend_get_constant_str(ZEND_STRL("SWOOLE_LIBRARY"));
    if (enable_library == NULL || !zval_is_true(enable_library)) {
        php_swoole_load_library();
    }

    /* init reactor and register event wait */
    php_swoole_check_reactor();

    /* replace interrupt function */
    orig_interrupt_function = zend_interrupt_function;
    zend_interrupt_function = coro_interrupt_function;

    if (SWOOLE_G(enable_preemptive_scheduler) || config.enable_preemptive_scheduler) {
        /* create a thread to interrupt the coroutine that takes up too much time */
        interrupt_thread_start();
    }

    if (config.hook_flags) {
        enable_hook(config.hook_flags);
    }

    disable_unsafe_function();

    /* deactivate when reactor free */
    sw_reactor()->add_destroy_callback(deactivate, nullptr);
    Coroutine::activate();

    Coroutine::set_on_yield(on_yield);
    Coroutine::set_on_resume(on_resume);
    Coroutine::set_on_close(on_close);

    activated = true;
}

void PHPCoroutine::deactivate(void *ptr) {
    if (sw_unlikely(!activated)) {
        return;
    }
    activated = false;
    interrupt_thread_stop();
    /**
     * reset runtime hook
     */
    disable_hook();

    Coroutine::set_on_yield(nullptr);
    Coroutine::set_on_resume(nullptr);
    Coroutine::set_on_close(nullptr);

    zend_interrupt_function = orig_interrupt_function;

    if (config.enable_deadlock_check) {
        deadlock_check();
    }

    enable_unsafe_function();
    Coroutine::deactivate();
}

void PHPCoroutine::shutdown() {
    if (activated) {
        deactivate(nullptr);
    }
    if (options) {
        zend_array_destroy(options);
        options = nullptr;
    }
    free_main_context();
}

void PHPCoroutine::deadlock_check() {
    if (Coroutine::count() == 0) {
        return;
    }
    if (php_swoole_is_fatal_error() || (sw_reactor() && sw_reactor()->bailout)) {
        return;
    }
    if (SWOOLE_G(enable_library)) {
        zend::function::call("\\Swoole\\Coroutine\\deadlock_check", 0, nullptr);
    } else {
        printf("\n==================================================================="
               "\n [FATAL ERROR]: all coroutines (count: %lu) are asleep - deadlock!"
               "\n===================================================================\n",
               Coroutine::count());
    }
}

void PHPCoroutine::interrupt_thread_stop() {
    if (!interrupt_thread_running) {
        return;
    }
    interrupt_thread_running = false;
    interrupt_thread.join();
}

void PHPCoroutine::interrupt_thread_start() {
    if (interrupt_thread_running) {
        return;
    }
    zend_vm_interrupt = &EG(vm_interrupt);
    interrupt_thread_running = true;
    interrupt_thread = std::thread([]() {
        swoole_signal_block_all();
        while (interrupt_thread_running) {
            zend_atomic_bool_store(zend_vm_interrupt, 1);
            std::this_thread::sleep_for(std::chrono::milliseconds(MAX_EXEC_MSEC / 2));
        }
    });
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
inline void PHPCoroutine::save_vm_stack(PHPContext *ctx) {
    ctx->bailout = EG(bailout);
    ctx->vm_stack_top = EG(vm_stack_top);
    ctx->vm_stack_end = EG(vm_stack_end);
    ctx->vm_stack = EG(vm_stack);
    ctx->vm_stack_page_size = EG(vm_stack_page_size);
    ctx->execute_data = EG(current_execute_data);
    ctx->jit_trace_num = EG(jit_trace_num);
    ctx->error_handling = EG(error_handling);
    ctx->exception_class = EG(exception_class);
    ctx->exception = EG(exception);
#if PHP_VERSION_ID < 80100
    if (UNEXPECTED(BG(array_walk_fci).size != 0)) {
        if (!ctx->array_walk_fci) {
            ctx->array_walk_fci = (zend::Function *) emalloc(sizeof(*ctx->array_walk_fci));
        }
        memcpy(ctx->array_walk_fci, &BG(array_walk_fci), sizeof(*ctx->array_walk_fci));
        memset(&BG(array_walk_fci), 0, sizeof(*ctx->array_walk_fci));
    }
#endif
    if (UNEXPECTED(ctx->in_silence)) {
        ctx->tmp_error_reporting = EG(error_reporting);
        EG(error_reporting) = ctx->ori_error_reporting;
    }
#ifdef ZEND_CHECK_STACK_LIMIT
    ctx->stack_base = EG(stack_base);
    ctx->stack_limit = EG(stack_limit);
#endif
}

inline void PHPCoroutine::restore_vm_stack(PHPContext *ctx) {
    EG(bailout) = ctx->bailout;
    EG(vm_stack_top) = ctx->vm_stack_top;
    EG(vm_stack_end) = ctx->vm_stack_end;
    EG(vm_stack) = ctx->vm_stack;
    EG(vm_stack_page_size) = ctx->vm_stack_page_size;
    EG(current_execute_data) = ctx->execute_data;
    EG(jit_trace_num) = ctx->jit_trace_num;
    EG(error_handling) = ctx->error_handling;
    EG(exception_class) = ctx->exception_class;
    EG(exception) = ctx->exception;
#if PHP_VERSION_ID < 80100
    if (UNEXPECTED(ctx->array_walk_fci && ctx->array_walk_fci->fci.size != 0)) {
        memcpy(&BG(array_walk_fci), ctx->array_walk_fci, sizeof(*ctx->array_walk_fci));
        ctx->array_walk_fci->fci.size = 0;
    }
#endif
    if (UNEXPECTED(ctx->in_silence)) {
        EG(error_reporting) = ctx->tmp_error_reporting;
    }
#ifdef ZEND_CHECK_STACK_LIMIT
    EG(stack_base) = ctx->stack_base;
    EG(stack_limit) = ctx->stack_limit;
#endif
}

inline void PHPCoroutine::save_og(PHPContext *ctx) {
    if (OG(handlers).elements) {
        ctx->output_ptr = (zend_output_globals *) emalloc(sizeof(zend_output_globals));
        memcpy(ctx->output_ptr, SWOG, sizeof(zend_output_globals));
        php_output_activate();
    } else {
        ctx->output_ptr = nullptr;
    }
}

inline void PHPCoroutine::restore_og(PHPContext *ctx) {
    if (ctx->output_ptr) {
        memcpy(SWOG, ctx->output_ptr, sizeof(zend_output_globals));
        efree(ctx->output_ptr);
        ctx->output_ptr = nullptr;
    }
}

void PHPCoroutine::set_hook_flags(uint32_t flags) {
    zval options;
    array_init(&options);
    add_assoc_long(&options, "hook_flags", flags);

    if (PHPCoroutine::options) {
        zend_hash_merge(PHPCoroutine::options, Z_ARRVAL(options), nullptr, true);
        zval_ptr_dtor(&options);
    } else {
        PHPCoroutine::options = Z_ARRVAL(options);
    }

    config.hook_flags = flags;
}

void PHPCoroutine::save_context(PHPContext *ctx) {
    save_vm_stack(ctx);
    save_og(ctx);
}

void PHPCoroutine::restore_context(PHPContext *ctx) {
    restore_vm_stack(ctx);
    restore_og(ctx);
}

void PHPCoroutine::on_yield(void *arg) {
    PHPContext *ctx = (PHPContext *) arg;
    PHPContext *origin_ctx = get_origin_context(ctx);

#ifdef SWOOLE_COROUTINE_MOCK_FIBER_CONTEXT
    fiber_context_switch_try_notify(ctx, origin_ctx);
#endif
    save_context(ctx);
    restore_context(origin_ctx);

    if (ctx->on_yield) {
        (*ctx->on_yield)(ctx);
    }

    swoole_trace_log(SW_TRACE_COROUTINE, "from cid=%ld to cid=%ld", ctx->co->get_cid(), ctx->co->get_origin_cid());
}

void PHPCoroutine::on_resume(void *arg) {
    PHPContext *ctx = (PHPContext *) arg;
    PHPContext *current_ctx = get_context();

#ifdef SWOOLE_COROUTINE_MOCK_FIBER_CONTEXT
    fiber_context_switch_try_notify(current_ctx, ctx);
#endif
    save_context(current_ctx);
    restore_context(ctx);
    record_last_msec(ctx);

    if (ctx->on_resume) {
        (*ctx->on_resume)(ctx);
    }

    swoole_trace_log(SW_TRACE_COROUTINE, "from cid=%ld to cid=%ld", Coroutine::get_current_cid(), ctx->co->get_cid());
}

void PHPCoroutine::on_close(void *arg) {
    PHPContext *ctx = (PHPContext *) arg;
    if (ctx->on_close) {
        (*ctx->on_close)(ctx);
    }
    efree(ctx);
}

void PHPCoroutine::destroy_context(PHPContext *ctx) {
    PHPContext *origin_ctx = get_origin_context(ctx);
#ifdef SW_LOG_TRACE_OPEN
    // MUST be assigned here, the task memory may have been released
    long cid = ctx->co->get_cid();
    long origin_cid = ctx->co->get_origin_cid();
#endif

    if (swoole_isset_hook(SW_GLOBAL_HOOK_ON_CORO_STOP)) {
        swoole_call_hook(SW_GLOBAL_HOOK_ON_CORO_STOP, ctx);
    }

    if (OG(handlers).elements) {
        zend_bool no_headers = SG(request_info).no_headers;
        /* Do not send headers by SAPI */
        SG(request_info).no_headers = 1;
        if (OG(active)) {
            php_output_end_all();
        }
        php_output_deactivate();
        php_output_activate();
        SG(request_info).no_headers = no_headers;
    }
#if PHP_VERSION_ID < 80100
    if (ctx->array_walk_fci) {
        efree(ctx->array_walk_fci);
    }
#endif

    if (ctx->defer_tasks) {
        while (!ctx->defer_tasks->empty()) {
            zend::Function *defer_fci = ctx->defer_tasks->top();
            ctx->defer_tasks->pop();
            sw_zend_fci_cache_discard(&defer_fci->fci_cache);
            efree(defer_fci);
        }
        delete ctx->defer_tasks;
        ctx->defer_tasks = nullptr;
    }

    // Release resources
    if (ctx->context) {
        zend_object *context = ctx->context;
        ctx->context = (zend_object *) ~0;
        OBJ_RELEASE(context);
    }

    Z_TRY_DELREF(ctx->fci.function_name);
    ZVAL_UNDEF(&ctx->fci.function_name);
    sw_zend_fci_cache_discard(&ctx->fci_cache);

    Z_TRY_DELREF(ctx->return_value);

#ifdef SWOOLE_COROUTINE_MOCK_FIBER_CONTEXT
    fiber_context_switch_try_notify(ctx, origin_ctx);
    fiber_context_try_destroy(ctx);
#endif

    swoole_trace_log(SW_TRACE_COROUTINE,
                     "coro close cid=%ld and resume to %ld, %zu remained. usage size: %zu. malloc size: %zu",
                     cid,
                     origin_cid,
                     (uintmax_t) Coroutine::count() - 1,
                     (uintmax_t) zend_memory_usage(0),
                     (uintmax_t) zend_memory_usage(1));

    zend_vm_stack_destroy();
    restore_context(origin_ctx);
}

void PHPCoroutine::main_func(void *_args) {
    bool exception_caught = false;
    Args *args = (Args *) _args;
    PHPContext *ctx = create_context(args);

    zend_first_try {
        swoole_trace_log(SW_TRACE_COROUTINE,
                         "Create coro id: %ld, origin cid: %ld, coro total count: %zu, heap size: %zu",
                         ctx->co->get_cid(),
                         ctx->co->get_origin_cid(),
                         (uintmax_t) Coroutine::count(),
                         (uintmax_t) zend_memory_usage(0));

        if (swoole_isset_hook(SW_GLOBAL_HOOK_ON_CORO_START)) {
            swoole_call_hook(SW_GLOBAL_HOOK_ON_CORO_START, ctx);
        }

#ifdef SWOOLE_COROUTINE_MOCK_FIBER_CONTEXT
        if (EXPECTED(SWOOLE_G(enable_fiber_mock) && ctx->fci_cache.function_handler->type == ZEND_USER_FUNCTION)) {
            zend_execute_data *tmp = EG(current_execute_data);
            zend_execute_data call = {};
            EG(current_execute_data) = &call;
            EG(current_execute_data)->opline = ctx->fci_cache.function_handler->op_array.opcodes;
            call.func = ctx->fci_cache.function_handler;
            fiber_context_switch_try_notify(get_origin_context(ctx), ctx);
            EG(current_execute_data) = tmp;
        }
#endif
        zend_call_function(&ctx->fci, &ctx->fci_cache);

        // Catch exception in main function of the coroutine
        exception_caught = catch_exception();

        // The defer tasks still need to be executed after an exception occurs
        if (ctx->defer_tasks) {
            std::stack<zend::Function *> *tasks = ctx->defer_tasks;
            while (!tasks->empty()) {
                zend::Function *defer_fci = tasks->top();
                tasks->pop();
                if (Z_TYPE_P(&ctx->return_value) != IS_UNDEF) {
                    defer_fci->fci.param_count = 1;
                    defer_fci->fci.params = &ctx->return_value;
                }
                if (UNEXPECTED(sw_zend_call_function_anyway(&defer_fci->fci, &defer_fci->fci_cache) != SUCCESS)) {
                    php_swoole_fatal_error(E_WARNING, "defer callback handler error");
                }
                if (EG(exception)) {
                    zend_bailout();
                }
                sw_zend_fci_cache_discard(&defer_fci->fci_cache);
                efree(defer_fci);
            }
            delete ctx->defer_tasks;
            ctx->defer_tasks = nullptr;
        }
    }
    zend_catch {
        // zend_bailout is executed in the c function
        catch_exception();
        exception_caught = true;
    }
    zend_end_try();
    destroy_context(ctx);
    if (exception_caught) {
        bailout();
    }
}

long PHPCoroutine::create(zend_fcall_info_cache *fci_cache, uint32_t argc, zval *argv, zval *callable) {
    if (sw_unlikely(Coroutine::count() >= config.max_num)) {
        php_swoole_fatal_error(E_WARNING, "exceed max number of coroutine %zu", (uintmax_t) Coroutine::count());
        return Coroutine::ERR_LIMIT;
    }
    if (sw_unlikely(!fci_cache || !fci_cache->function_handler)) {
        php_swoole_fatal_error(E_ERROR, "invalid function call info cache");
        return Coroutine::ERR_INVALID;
    }
    zend_uchar type = fci_cache->function_handler->type;
    if (sw_unlikely(type != ZEND_USER_FUNCTION && type != ZEND_INTERNAL_FUNCTION)) {
        php_swoole_fatal_error(E_ERROR, "invalid function type %u", fci_cache->function_handler->type);
        return Coroutine::ERR_INVALID;
    }

    if (sw_unlikely(!activated)) {
        activate();
    }

    Args _args;
    _args.fci_cache = fci_cache;
    _args.argv = argv;
    _args.argc = argc;
    _args.callable = callable;
    save_context(get_context());

    return Coroutine::create(main_func, (void *) &_args);
}

void PHPCoroutine::defer(zend::Function *fci) {
    PHPContext *ctx = get_context();
    if (ctx->defer_tasks == nullptr) {
        ctx->defer_tasks = new std::stack<zend::Function *>;
    }
    ctx->defer_tasks->push(fci);
}

#ifdef SWOOLE_COROUTINE_MOCK_FIBER_CONTEXT

void PHPCoroutine::fiber_context_init(PHPContext *ctx) {
    zend_fiber_context *fiber_context = (zend_fiber_context *) emalloc(sizeof(*fiber_context));
    fiber_context->handle = (void *) -1;
    fiber_context->kind = (void *) -1;
    fiber_context->function = (zend_fiber_coroutine) -1;
    fiber_context->stack = (zend_fiber_stack *) -1;
    ctx->fiber_context = fiber_context;

    zend_observer_fiber_init_notify(fiber_context);
}

void PHPCoroutine::fiber_context_try_init(PHPContext *ctx) {
    if (EXPECTED(!SWOOLE_G(enable_fiber_mock))) {
        return;
    }
    fiber_context_init(ctx);
}

void PHPCoroutine::fiber_context_destroy(PHPContext *ctx) {
    zend_observer_fiber_destroy_notify(ctx->fiber_context);

    if (ctx->fiber_context != NULL) {
        efree(ctx->fiber_context);
    }
}

void PHPCoroutine::fiber_context_try_destroy(PHPContext *ctx) {
    if (EXPECTED(!SWOOLE_G(enable_fiber_mock))) {
        return;
    }
    fiber_context_destroy(ctx);
}

zend_fiber_status PHPCoroutine::get_fiber_status(PHPContext *ctx) {
    switch (ctx->co->get_state()) {
    case Coroutine::STATE_INIT:
        return ZEND_FIBER_STATUS_INIT;
    case Coroutine::STATE_WAITING:
        return ZEND_FIBER_STATUS_SUSPENDED;
    case Coroutine::STATE_RUNNING:
        return ZEND_FIBER_STATUS_RUNNING;
    case Coroutine::STATE_END:
        return ZEND_FIBER_STATUS_DEAD;
    default:
        php_swoole_fatal_error(E_ERROR, "Unexpected state when get fiber status");
        return ZEND_FIBER_STATUS_DEAD;
    }
}

void PHPCoroutine::fiber_context_switch_notify(PHPContext *from, PHPContext *to) {
    zend_fiber_context *from_context = from->fiber_context;
    zend_fiber_context *to_context = to->fiber_context;

    from_context->status = get_fiber_status(from);
    to_context->status = get_fiber_status(to);

    if (!to->fiber_init_notified) {
        to_context->status = ZEND_FIBER_STATUS_INIT;
        zend_observer_fiber_switch_notify(from_context, to_context);
        to_context->status = get_fiber_status(to);
        to->fiber_init_notified = true;
    } else {
        zend_observer_fiber_switch_notify(from_context, to_context);
    }
}

void PHPCoroutine::fiber_context_switch_try_notify(PHPContext *from, PHPContext *to) {
    if (EXPECTED(!SWOOLE_G(enable_fiber_mock))) {
        return;
    }
    fiber_context_switch_notify(from, to);
}
#endif /* SWOOLE_COROUTINE_MOCK_FIBER_CONTEXT */

#ifdef ZEND_CHECK_STACK_LIMIT
void *PHPCoroutine::stack_limit(PHPContext *ctx) {
#ifdef SW_USE_THREAD_CONTEXT
    return nullptr;
#else
    zend_ulong reserve = EG(reserved_stack_size);

#ifdef __APPLE__
    /* On Apple Clang, the stack probing function ___chkstk_darwin incorrectly
     * probes a location that is twice the entered function's stack usage away
     * from the stack pointer, when using an alternative stack.
     * https://openradar.appspot.com/radar?id=5497722702397440
     */
    reserve = reserve * 2;
#endif

    if (!ctx->co) {
        return nullptr;
    }

    /* stack->pointer is the end of the stack */
    return (int8_t *) ctx->co->get_ctx().get_stack() + reserve;
#endif
}
void *PHPCoroutine::stack_base(PHPContext *ctx) {
#ifdef SW_USE_THREAD_CONTEXT
    return nullptr;
#else
    if (!ctx->co) {
        return nullptr;
    }

    return (void *) ((uintptr_t) ctx->co->get_ctx().get_stack() + ctx->co->get_ctx().get_stack_size());
#endif
}
#endif /* ZEND_CHECK_STACK_LIMIT */

/* hook autoload */

static zend_class_entry *(*original_zend_autoload)(zend_string *name, zend_string *lc_name);

struct AutoloadContext {
    Coroutine *coroutine;
    zend_class_entry *ce;
};

struct AutoloadQueue {
    Coroutine *coroutine;
    std::queue<AutoloadContext *> *queue;
};

static zend_class_entry *swoole_coroutine_autoload(zend_string *name, zend_string *lc_name) {
    auto current = Coroutine::get_current();
    if (!current) {
        return original_zend_autoload(name, lc_name);
    }

    ZEND_ASSERT(EG(in_autoload) != nullptr);
    zend_hash_del(EG(in_autoload), lc_name);

    if (UNEXPECTED(SWOOLE_G(in_autoload) == nullptr)) {
        ALLOC_HASHTABLE(SWOOLE_G(in_autoload));
        zend_hash_init(SWOOLE_G(in_autoload), 8, nullptr, nullptr, 0);
    }
    zval *z_queue = zend_hash_find(SWOOLE_G(in_autoload), lc_name);
    if (z_queue != nullptr) {
        auto queue = (AutoloadQueue *) Z_PTR_P(z_queue);
        if (queue->coroutine == current) {
            return nullptr;
        }
        AutoloadContext context;
        context.coroutine = current;
        context.ce = nullptr;
        queue->queue->push(&context);
        current->yield();
        return context.ce;
    }
    AutoloadQueue queue;
    queue.coroutine = current;
    std::queue<AutoloadContext *> queue_object;
    queue.queue = &queue_object;

    zend_hash_add_ptr(SWOOLE_G(in_autoload), lc_name, &queue);
    zend_class_entry *ce = original_zend_autoload(name, lc_name);
    zend_hash_del(SWOOLE_G(in_autoload), lc_name);

    AutoloadContext *pending_context = nullptr;
    while (!queue_object.empty()) {
        pending_context = queue_object.front();
        queue_object.pop();
        pending_context->ce = ce;
        pending_context->coroutine->resume();
    }
    return ce;
}

void php_swoole_coroutine_minit(int module_number) {
    SW_INIT_CLASS_ENTRY_BASE(swoole_coroutine_util, "Swoole\\Coroutine", "Co", swoole_coroutine_methods, nullptr);
    SW_SET_CLASS_CREATE(swoole_coroutine_util, sw_zend_create_object_deny);

    SW_INIT_CLASS_ENTRY_BASE(
        swoole_coroutine_iterator, "Swoole\\Coroutine\\Iterator", "Co\\Iterator", nullptr, spl_ce_ArrayIterator);
    SW_INIT_CLASS_ENTRY_BASE(
        swoole_coroutine_context, "Swoole\\Coroutine\\Context", "Co\\Context", nullptr, spl_ce_ArrayObject);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_DEFAULT_MAX_CORO_NUM", SW_DEFAULT_MAX_CORO_NUM);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_MAX_NUM_LIMIT", Coroutine::MAX_NUM_LIMIT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_INIT", Coroutine::STATE_INIT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_WAITING", Coroutine::STATE_WAITING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_RUNNING", Coroutine::STATE_RUNNING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_END", Coroutine::STATE_END);

    // prohibit exit in coroutine
    SW_INIT_CLASS_ENTRY_EX(
        swoole_exit_exception, "Swoole\\ExitException", nullptr, swoole_exit_exception_methods, swoole_exception);
    zend_declare_property_long(swoole_exit_exception_ce, ZEND_STRL("flags"), 0, ZEND_ACC_PRIVATE);
    zend_declare_property_long(swoole_exit_exception_ce, ZEND_STRL("status"), 0, ZEND_ACC_PRIVATE);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_EXIT_IN_COROUTINE", SW_EXIT_IN_COROUTINE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_EXIT_IN_SERVER", SW_EXIT_IN_SERVER);

    /* hook autoload */
    original_zend_autoload = zend_autoload;
    zend_autoload = swoole_coroutine_autoload;
    SWOOLE_G(in_autoload) = nullptr;
}

void php_swoole_coroutine_rinit() {
    if (SWOOLE_G(cli)) {
#if PHP_VERSION_ID < 80400
        ori_exit_handler = zend_get_user_opcode_handler(ZEND_EXIT);
        zend_set_user_opcode_handler(ZEND_EXIT, coro_exit_handler);
#endif

        ori_begin_silence_handler = zend_get_user_opcode_handler(ZEND_BEGIN_SILENCE);
        zend_set_user_opcode_handler(ZEND_BEGIN_SILENCE, coro_begin_silence_handler);

        ori_end_silence_handler = zend_get_user_opcode_handler(ZEND_END_SILENCE);
        zend_set_user_opcode_handler(ZEND_END_SILENCE, coro_end_silence_handler);
    }

    PHPCoroutine::init_main_context();
}

void php_swoole_coroutine_rshutdown() {
    if (SWOOLE_G(in_autoload)) {
        zend_hash_destroy(SWOOLE_G(in_autoload));
        FREE_HASHTABLE(SWOOLE_G(in_autoload));
        SWOOLE_G(in_autoload) = nullptr;
    }

    PHPCoroutine::shutdown();
}

static PHP_METHOD(swoole_exit_exception, getFlags) {
    SW_RETURN_PROPERTY("flags");
}

static PHP_METHOD(swoole_exit_exception, getStatus) {
    SW_RETURN_PROPERTY("status");
}

PHP_FUNCTION(swoole_coroutine_create) {
    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;

    ZEND_PARSE_PARAMETERS_START(1, -1)
    Z_PARAM_FUNC(fci, fci_cache)
    Z_PARAM_VARIADIC('*', fci.params, fci.param_count)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (sw_unlikely(SWOOLE_G(req_status) == PHP_SWOOLE_CALL_USER_SHUTDOWNFUNC_BEGIN)) {
        zend_function *func = (zend_function *) EG(current_execute_data)->prev_execute_data->func;
        if (func->common.function_name &&
            sw_unlikely(memcmp(ZSTR_VAL(func->common.function_name), ZEND_STRS("__destruct")) == 0)) {
            php_swoole_fatal_error(E_ERROR, "can not use coroutine in __destruct after php_request_shutdown");
            RETURN_FALSE;
        }
    }

    long cid = PHPCoroutine::create(&fci_cache, fci.param_count, fci.params, &fci.function_name);
    if (sw_likely(cid > 0)) {
        RETURN_LONG(cid);
    } else {
        RETURN_FALSE;
    }
}

PHP_FUNCTION(swoole_coroutine_defer) {
    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;
    zend::Function *defer_fci;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_FUNC(fci, fci_cache)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Coroutine::get_current_safe();
    defer_fci = (zend::Function *) emalloc(sizeof(zend::Function));
    defer_fci->fci = fci;
    defer_fci->fci_cache = fci_cache;
    sw_zend_fci_cache_persist(&defer_fci->fci_cache);
    PHPCoroutine::defer(defer_fci);
}

static PHP_METHOD(swoole_coroutine, stats) {
    array_init(return_value);
    add_assoc_long_ex(return_value, ZEND_STRL("event_num"), sw_reactor() ? sw_reactor()->get_event_num() : 0);
    add_assoc_long_ex(
        return_value, ZEND_STRL("signal_listener_num"), SwooleTG.signal_listener_num + SwooleTG.co_signal_listener_num);

    if (SwooleTG.async_threads) {
        add_assoc_long_ex(return_value, ZEND_STRL("aio_task_num"), SwooleTG.async_threads->get_task_num());
        add_assoc_long_ex(return_value, ZEND_STRL("aio_worker_num"), SwooleTG.async_threads->get_worker_num());
        add_assoc_long_ex(return_value, ZEND_STRL("aio_queue_size"), SwooleTG.async_threads->get_queue_size());
    } else {
        add_assoc_long_ex(return_value, ZEND_STRL("aio_task_num"), 0);
        add_assoc_long_ex(return_value, ZEND_STRL("aio_worker_num"), 0);
        add_assoc_long_ex(return_value, ZEND_STRL("aio_queue_size"), 0);
    }
    add_assoc_long_ex(return_value, ZEND_STRL("c_stack_size"), Coroutine::get_stack_size());
    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_num"), Coroutine::count());
    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_peak_num"), Coroutine::get_peak_num());
    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_last_cid"), Coroutine::get_last_cid());
}

PHP_METHOD(swoole_coroutine, getCid) {
    RETURN_LONG(PHPCoroutine::get_cid());
}

PHP_METHOD(swoole_coroutine, getPcid) {
    zend_long cid = 0;
    zend_long ret;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(cid)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    ret = PHPCoroutine::get_pcid(cid);
    if (ret == 0) {
        RETURN_FALSE;
    }

    RETURN_LONG(ret);
}

static PHP_METHOD(swoole_coroutine, getContext) {
    zend_long cid = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(cid)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    PHPContext *ctx =
        (PHPContext *) (EXPECTED(cid == 0) ? Coroutine::get_current_task() : Coroutine::get_task_by_cid(cid));
    if (UNEXPECTED(!ctx)) {
        swoole_set_last_error(SW_ERROR_CO_NOT_EXISTS);
        RETURN_NULL();
    }
    if (UNEXPECTED(ctx->context == (zend_object *) ~0)) {
        /* bad context (has been destroyed), see: https://github.com/swoole/swoole-src/issues/2991 */
        php_swoole_fatal_error(E_WARNING, "Context of this coroutine has been destroyed");
        RETURN_NULL();
    }
    if (UNEXPECTED(!ctx->context)) {
        object_init_ex(return_value, swoole_coroutine_context_ce);
        ctx->context = Z_OBJ_P(return_value);
    }
    GC_ADDREF(ctx->context);
    RETURN_OBJ(ctx->context);
}

static PHP_METHOD(swoole_coroutine, getElapsed) {
    zend_long cid = 0;
    zend_long ret;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(cid)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    ret = PHPCoroutine::get_elapsed(cid);
    RETURN_LONG(ret);
}

static PHP_METHOD(swoole_coroutine, getStackUsage) {
    zend_long cid = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(cid)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    ssize_t usage = PHPCoroutine::get_stack_usage(cid);
    if (usage < 0) {
        RETURN_FALSE;
    }
    RETURN_LONG(usage);
}

static PHP_METHOD(swoole_coroutine, exists) {
    zend_long cid;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(cid)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(Coroutine::get_by_cid(cid) != nullptr);
}

static PHP_METHOD(swoole_coroutine, resume) {
    zend_long cid;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(cid)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    auto coroutine_iterator = user_yield_coros.find(cid);
    if (coroutine_iterator == user_yield_coros.end()) {
        php_swoole_fatal_error(E_WARNING, "can not resume the coroutine which is in IO operation or non-existent");
        RETURN_FALSE;
    }

    Coroutine *co = coroutine_iterator->second;
    user_yield_coros.erase(cid);
    co->resume();

    RETURN_TRUE;
}

static PHP_METHOD(swoole_coroutine, yield) {
    Coroutine *co = Coroutine::get_current_safe();
    user_yield_coros[co->get_cid()] = co;

    Coroutine::CancelFunc cancel_fn = [](Coroutine *co) {
        user_yield_coros.erase(co->get_cid());
        co->resume();
        return true;
    };
    co->yield(&cancel_fn);
    if (co->is_canceled()) {
        swoole_set_last_error(SW_ERROR_CO_CANCELED);
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_coroutine, join) {
    Coroutine *co = Coroutine::get_current_safe();
    zval *cid_array;
    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_ARRAY(cid_array)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (php_swoole_array_length(cid_array) == 0) {
        swoole_set_last_error(SW_ERROR_INVALID_PARAMS);
        RETURN_FALSE;
    }

    std::set<PHPContext *> co_set;
    bool *canceled = new bool(false);

    PHPContext::SwapCallback join_fn = [&co_set, canceled, co](PHPContext *task) {
        co_set.erase(task);
        if (!co_set.empty()) {
            return;
        }
        swoole_event_defer(
            [co, canceled](void *) {
                if (*canceled == false) {
                    co->resume();
                }
                delete canceled;
            },
            nullptr);
    };

    zval *zcid;
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(cid_array), zcid) {
        long cid = zval_get_long(zcid);
        if (co->get_cid() == cid) {
            php_swoole_error_ex(E_WARNING, SW_ERROR_WRONG_OPERATION, "can not join self");
            delete canceled;
            RETURN_FALSE;
        }
        auto ctx = PHPCoroutine::get_context_by_cid(cid);
        if (ctx == nullptr) {
            continue;
        }
        if (ctx->on_close) {
            swoole_set_last_error(SW_ERROR_CO_HAS_BEEN_BOUND);
            delete canceled;
            RETURN_FALSE;
        }
        ctx->on_close = &join_fn;
        co_set.insert(ctx);
    }
    ZEND_HASH_FOREACH_END();

    if (co_set.empty()) {
        swoole_set_last_error(SW_ERROR_INVALID_PARAMS);
        delete canceled;
        RETURN_FALSE;
    }

    if (!co->yield_ex(timeout)) {
        if (!co_set.empty()) {
            for (auto ctx : co_set) {
                ctx->on_close = nullptr;
            }
            delete canceled;
        } else {
            *canceled = true;
        }
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_coroutine, cancel) {
    zend_long cid;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(cid)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Coroutine *co = swoole_coroutine_get(cid);
    if (!co) {
        swoole_set_last_error(SW_ERROR_CO_NOT_EXISTS);
        RETURN_FALSE;
    }
    RETURN_BOOL(co->cancel());
}

static PHP_METHOD(swoole_coroutine, isCanceled) {
    Coroutine *co = Coroutine::get_current_safe();
    RETURN_BOOL(co->is_canceled());
}

PHP_FUNCTION(swoole_test_kernel_coroutine) {
    if (!PHPCoroutine::is_activated()) {
        RETURN_FALSE;
    }

    zend_long count = 100;
    double sleep_time = 1.0;

    ZEND_PARSE_PARAMETERS_START(0, 2)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(count)
    Z_PARAM_DOUBLE(sleep_time)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Coroutine::create([=](void *ptr) {
        SW_LOOP_N(count) {
            System::sleep(sleep_time);
        }
    });
}

static PHP_METHOD(swoole_coroutine, getBackTrace) {
    zend_long cid = 0;
    zend_long options = DEBUG_BACKTRACE_PROVIDE_OBJECT;
    zend_long limit = 0;

    ZEND_PARSE_PARAMETERS_START(0, 3)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(cid)
    Z_PARAM_LONG(options)
    Z_PARAM_LONG(limit)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (!cid || cid == PHPCoroutine::get_cid()) {
        zend_fetch_debug_backtrace(return_value, 0, options, limit);
    } else {
        PHPContext *task = (PHPContext *) PHPCoroutine::get_context_by_cid(cid);
        if (UNEXPECTED(!task)) {
            swoole_set_last_error(SW_ERROR_CO_NOT_EXISTS);
            RETURN_FALSE;
        }
        zend_execute_data *ex_backup = EG(current_execute_data);
        EG(current_execute_data) = task->execute_data;
        zend_fetch_debug_backtrace(return_value, 0, options, limit);
        EG(current_execute_data) = ex_backup;
    }
}

static PHP_METHOD(swoole_coroutine, printBackTrace) {
    zend_long cid = 0;
    zend_long options = 0;
    zend_long limit = 0;

    ZEND_PARSE_PARAMETERS_START(0, 3)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(cid)
    Z_PARAM_LONG(options)
    Z_PARAM_LONG(limit)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zval argv[2];
    ZVAL_LONG(&argv[0], options);
    ZVAL_LONG(&argv[1], limit);

    if (!cid || cid == PHPCoroutine::get_cid()) {
        zend::function::call("debug_print_backtrace", 2, argv);
    } else {
        PHPContext *ctx = (PHPContext *) PHPCoroutine::get_context_by_cid(cid);
        if (UNEXPECTED(!ctx)) {
            swoole_set_last_error(SW_ERROR_CO_NOT_EXISTS);
            RETURN_FALSE;
        }
        zend_execute_data *ex_backup = EG(current_execute_data);
        EG(current_execute_data) = ctx->execute_data;
        zend::function::call("debug_print_backtrace", 2, argv);
        EG(current_execute_data) = ex_backup;
    }
}

static PHP_METHOD(swoole_coroutine, list) {
    zval zlist;
    array_init(&zlist);
    for (auto &co : Coroutine::coroutines) {
        add_next_index_long(&zlist, co.second->get_cid());
    }
    object_init_ex(return_value, swoole_coroutine_iterator_ce);
    sw_zend_call_method_with_1_params(return_value,
                                      swoole_coroutine_iterator_ce,
                                      &swoole_coroutine_iterator_ce->constructor,
                                      "__construct",
                                      nullptr,
                                      &zlist);
    zval_ptr_dtor(&zlist);
}

#ifdef SW_CORO_TIME
static PHP_METHOD(swoole_coroutine, getExecuteTime) {
    RETURN_LONG(PHPCoroutine::get_execute_time());
}
#endif

PHP_METHOD(swoole_coroutine, enableScheduler) {
    RETURN_BOOL(PHPCoroutine::enable_scheduler());
}

PHP_METHOD(swoole_coroutine, disableScheduler) {
    RETURN_BOOL(PHPCoroutine::disable_scheduler());
}

/**
 * for gdb
 */
zend_executor_globals *php_swoole_get_executor_globals() {
    return (zend_executor_globals *) &EG(uninitialized_zval);
}
