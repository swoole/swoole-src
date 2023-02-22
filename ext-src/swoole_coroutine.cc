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
#include "php_swoole_coroutine_system.h"

#include "swoole_server.h"
#include "swoole_signal.h"

#include "zend_builtin_functions.h"
#include "ext/spl/spl_array.h"

#include <unordered_map>
#include <chrono>

using std::unordered_map;
using swoole::Coroutine;
using swoole::PHPContext;
using swoole::PHPCoroutine;
using swoole::coroutine::Socket;
using swoole::coroutine::System;

#define PHP_CORO_TASK_SLOT                                                                                             \
    ((int) ((ZEND_MM_ALIGNED_SIZE(sizeof(PHPContext)) + ZEND_MM_ALIGNED_SIZE(sizeof(zval)) - 1) /                      \
            ZEND_MM_ALIGNED_SIZE(sizeof(zval))))

enum sw_exit_flags { SW_EXIT_IN_COROUTINE = 1 << 1, SW_EXIT_IN_SERVER = 1 << 2 };

bool PHPCoroutine::activated = false;
uint32_t PHPCoroutine::concurrency = 0;
zend_array *PHPCoroutine::options = nullptr;

PHPCoroutine::Config PHPCoroutine::config{
    SW_DEFAULT_MAX_CORO_NUM,
    UINT_MAX,
    0,
    false,
    true,
};

PHPContext PHPCoroutine::main_task{};
std::thread PHPCoroutine::interrupt_thread;
bool PHPCoroutine::interrupt_thread_running = false;

extern void php_swoole_load_library();

static zend_atomic_bool *zend_vm_interrupt = nullptr;
static user_opcode_handler_t ori_exit_handler = nullptr;
static user_opcode_handler_t ori_begin_silence_handler = nullptr;
static user_opcode_handler_t ori_end_silence_handler = nullptr;
static unordered_map<long, Coroutine *> user_yield_coros;

static void (*orig_interrupt_function)(zend_execute_data *execute_data) = nullptr;
static void (*orig_error_function)(int type,
                                   error_filename_t *error_filename,
                                   const uint32_t error_lineno,
                                   ZEND_ERROR_CB_LAST_ARG_D) = nullptr;

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
SW_EXTERN_C_END

// clang-format off
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_set, 0, 0, 1)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_create, 0, 0, 1)
    ZEND_ARG_CALLABLE_INFO(0, func, 0)
    ZEND_ARG_VARIADIC_INFO(0, params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_cancel, 0, 0, 1)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_resume, 0, 0, 1)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_join, 0, 0, 1)
    ZEND_ARG_INFO(0, cid_array)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_exists, 0, 0, 1)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getContext, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_defer, 0, 0, 1)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getBackTrace, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
    ZEND_ARG_INFO(0, options)
    ZEND_ARG_INFO(0, limit)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_printBackTrace, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
    ZEND_ARG_INFO(0, options)
    ZEND_ARG_INFO(0, limit)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getPcid, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getElapsed, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getStackUsage, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_coroutine_methods[] =
{
    /**
     * Coroutine Core API
     */
    ZEND_FENTRY(create, ZEND_FN(swoole_coroutine_create), arginfo_swoole_coroutine_create, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(defer, ZEND_FN(swoole_coroutine_defer), arginfo_swoole_coroutine_defer, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_scheduler, set, arginfo_swoole_coroutine_set, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_scheduler, getOptions, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, exists, arginfo_swoole_coroutine_exists, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, yield, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, cancel, arginfo_swoole_coroutine_cancel, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, join, arginfo_swoole_coroutine_join, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, isCanceled, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_MALIAS(swoole_coroutine, suspend, yield, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, resume, arginfo_swoole_coroutine_resume, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, stats, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, getCid, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_MALIAS(swoole_coroutine, getuid, getCid, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, getPcid, arginfo_swoole_coroutine_getPcid, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, getContext, arginfo_swoole_coroutine_getContext, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, getBackTrace, arginfo_swoole_coroutine_getBackTrace, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, printBackTrace, arginfo_swoole_coroutine_printBackTrace, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, getElapsed, arginfo_swoole_coroutine_getElapsed, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, getStackUsage, arginfo_swoole_coroutine_getStackUsage, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, list, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_MALIAS(swoole_coroutine, listCoroutines, list, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, enableScheduler, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine, disableScheduler, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    /**
     * Coroutine System API
     */
    ZEND_FENTRY(gethostbyname, ZEND_FN(swoole_coroutine_gethostbyname), arginfo_swoole_coroutine_system_gethostbyname, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(dnsLookup, ZEND_FN(swoole_async_dns_lookup_coro), arginfo_swoole_coroutine_system_dnsLookup, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, exec, arginfo_swoole_coroutine_system_exec, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, sleep, arginfo_swoole_coroutine_system_sleep, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, getaddrinfo, arginfo_swoole_coroutine_system_getaddrinfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, statvfs, arginfo_swoole_coroutine_system_statvfs, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, readFile, arginfo_swoole_coroutine_system_readFile, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, writeFile, arginfo_swoole_coroutine_system_writeFile, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, wait, arginfo_swoole_coroutine_system_wait, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, waitPid, arginfo_swoole_coroutine_system_waitPid, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, waitSignal, arginfo_swoole_coroutine_system_waitSignal, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, waitEvent, arginfo_swoole_coroutine_system_waitEvent, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    /* Deprecated file methods */
    PHP_ME(swoole_coroutine_system, fread, arginfo_swoole_coroutine_system_fread, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC | ZEND_ACC_DEPRECATED)
    PHP_ME(swoole_coroutine_system, fgets, arginfo_swoole_coroutine_system_fgets, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC | ZEND_ACC_DEPRECATED)
    PHP_ME(swoole_coroutine_system, fwrite, arginfo_swoole_coroutine_system_fwrite, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC | ZEND_ACC_DEPRECATED)
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
    PHP_ME(swoole_exit_exception, getFlags, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_exit_exception, getStatus, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

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

void PHPCoroutine::init() {
    Coroutine::set_on_yield(on_yield);
    Coroutine::set_on_resume(on_resume);
    Coroutine::set_on_close(on_close);
}

void PHPCoroutine::error_cb(int type,
                            error_filename_t *error_filename,
                            const uint32_t error_lineno,
                            ZEND_ERROR_CB_LAST_ARG_D) {
    if (sw_unlikely(type & E_FATAL_ERRORS)) {
        if (sw_reactor()) {
            sw_reactor()->running = false;
            sw_reactor()->bailout = true;
        }
        if (swoole_coroutine_is_in()) {
            // update the last coroutine's info
            save_task(get_context());
            Coroutine::bailout([=]() {
                zend_error_cb = orig_error_function;
                orig_error_function(type, error_filename, error_lineno, ZEND_ERROR_CB_LAST_ARG_RELAY);
                zend_bailout();
            });
        }
    }
    if (orig_error_function) {
        orig_error_function(type, error_filename, error_lineno, ZEND_ERROR_CB_LAST_ARG_RELAY);
    }
}

void PHPCoroutine::catch_exception() {
    if (UNEXPECTED(EG(exception))) {
        zend_error_cb = orig_error_function;
        // the exception error messages MUST be output on the current coroutine stack
        zend_exception_error(EG(exception), E_ERROR);
#if PHP_VERSION_ID >= 80000
        zend_bailout();
#endif
    }
}

void PHPCoroutine::activate() {
    if (sw_unlikely(activated)) {
        return;
    }

    if (zend_hash_str_find_ptr(&module_registry, ZEND_STRL("xdebug"))) {
        php_swoole_fatal_error(
            E_WARNING,
            "Using Xdebug in coroutines is extremely dangerous, please notice that it may lead to coredump!");
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

    /* replace the error function to save execute_data */
    orig_error_function = zend_error_cb;
    zend_error_cb = PHPCoroutine::error_cb;

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
    activated = true;
}

void PHPCoroutine::deactivate(void *ptr) {
    interrupt_thread_stop();
    /**
     * reset runtime hook
     */
    disable_hook();

    zend_interrupt_function = orig_interrupt_function;
    zend_error_cb = orig_error_function;

    if (config.enable_deadlock_check) {
        deadlock_check();
    }

    enable_unsafe_function();
    Coroutine::deactivate();
    activated = false;
}

void PHPCoroutine::shutdown() {
    interrupt_thread_stop();
    Coroutine::bailout(nullptr);
    if (options) {
        zend_array_destroy(options);
        options = nullptr;
    }
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

inline void PHPCoroutine::vm_stack_init(void) {
    uint32_t size = SW_DEFAULT_PHP_STACK_PAGE_SIZE;
    zend_vm_stack page = (zend_vm_stack) emalloc(size);

    page->top = ZEND_VM_STACK_ELEMENTS(page);
    page->end = (zval *) ((char *) page + size);
    page->prev = nullptr;

    EG(vm_stack) = page;
    EG(vm_stack)->top++;
    EG(vm_stack_top) = EG(vm_stack)->top;
    EG(vm_stack_end) = EG(vm_stack)->end;
#if PHP_VERSION_ID >= 70300
    EG(vm_stack_page_size) = size;
#endif
}

inline void PHPCoroutine::vm_stack_destroy(void) {
    zend_vm_stack stack = EG(vm_stack);

    while (stack != nullptr) {
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
inline void PHPCoroutine::save_vm_stack(PHPContext *task) {
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
#if PHP_VERSION_ID >= 80000
    task->jit_trace_num = EG(jit_trace_num);
#endif
    task->error_handling = EG(error_handling);
    task->exception_class = EG(exception_class);
    task->exception = EG(exception);
#if PHP_VERSION_ID < 80100
    if (UNEXPECTED(BG(array_walk_fci).size != 0)) {
        if (!task->array_walk_fci) {
            task->array_walk_fci = (zend::Function *) emalloc(sizeof(*task->array_walk_fci));
        }
        memcpy(task->array_walk_fci, &BG(array_walk_fci), sizeof(*task->array_walk_fci));
        memset(&BG(array_walk_fci), 0, sizeof(*task->array_walk_fci));
    }
#endif
    if (UNEXPECTED(task->in_silence)) {
        task->tmp_error_reporting = EG(error_reporting);
        EG(error_reporting) = task->ori_error_reporting;
    }
}

inline void PHPCoroutine::restore_vm_stack(PHPContext *task) {
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
#if PHP_VERSION_ID >= 80000
    EG(jit_trace_num) = task->jit_trace_num;
#endif
    EG(error_handling) = task->error_handling;
    EG(exception_class) = task->exception_class;
    EG(exception) = task->exception;
#if PHP_VERSION_ID < 80100
    if (UNEXPECTED(task->array_walk_fci && task->array_walk_fci->fci.size != 0)) {
        memcpy(&BG(array_walk_fci), task->array_walk_fci, sizeof(*task->array_walk_fci));
        task->array_walk_fci->fci.size = 0;
    }
#endif
    if (UNEXPECTED(task->in_silence)) {
        EG(error_reporting) = task->tmp_error_reporting;
    }
}

inline void PHPCoroutine::save_og(PHPContext *task) {
    if (OG(handlers).elements) {
        task->output_ptr = (zend_output_globals *) emalloc(sizeof(zend_output_globals));
        memcpy(task->output_ptr, SWOG, sizeof(zend_output_globals));
        php_output_activate();
    } else {
        task->output_ptr = nullptr;
    }
}

inline void PHPCoroutine::restore_og(PHPContext *task) {
    if (task->output_ptr) {
        memcpy(SWOG, task->output_ptr, sizeof(zend_output_globals));
        efree(task->output_ptr);
        task->output_ptr = nullptr;
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

void PHPCoroutine::save_task(PHPContext *task) {
    save_vm_stack(task);
    save_og(task);
}

void PHPCoroutine::restore_task(PHPContext *task) {
    restore_vm_stack(task);
    restore_og(task);
}

void PHPCoroutine::on_yield(void *arg) {
    PHPContext *task = (PHPContext *) arg;
    PHPContext *origin_task = get_origin_context(task);
    save_task(task);
    restore_task(origin_task);

    if (task->on_yield) {
        (*task->on_yield)(task);
    }

    swoole_trace_log(SW_TRACE_COROUTINE, "from cid=%ld to cid=%ld", task->co->get_cid(), task->co->get_origin_cid());
}

void PHPCoroutine::on_resume(void *arg) {
    PHPContext *task = (PHPContext *) arg;
    PHPContext *current_task = get_context();
    save_task(current_task);
    restore_task(task);
    record_last_msec(task);

    if (task->on_resume) {
        (*task->on_resume)(task);
    }

    swoole_trace_log(SW_TRACE_COROUTINE, "from cid=%ld to cid=%ld", Coroutine::get_current_cid(), task->co->get_cid());
}

void PHPCoroutine::on_close(void *arg) {
    PHPContext *task = (PHPContext *) arg;
    PHPContext *origin_task = get_origin_context(task);
#ifdef SW_LOG_TRACE_OPEN
    // MUST be assigned here, the task memory may have been released
    long cid = task->co->get_cid();
    long origin_cid = task->co->get_origin_cid();
#endif

    if (swoole_isset_hook(SW_GLOBAL_HOOK_ON_CORO_STOP)) {
        swoole_call_hook(SW_GLOBAL_HOOK_ON_CORO_STOP, task);
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
    if (task->array_walk_fci) {
        efree(task->array_walk_fci);
    }
#endif

    if (task->on_close) {
        (*task->on_close)(task);
    }

    if (task->pcid == -1) {
        concurrency--;
    }

    vm_stack_destroy();
    restore_task(origin_task);

    swoole_trace_log(SW_TRACE_COROUTINE,
                     "coro close cid=%ld and resume to %ld, %zu remained. usage size: %zu. malloc size: %zu",
                     cid,
                     origin_cid,
                     (uintmax_t) Coroutine::count() - 1,
                     (uintmax_t) zend_memory_usage(0),
                     (uintmax_t) zend_memory_usage(1));
}

void PHPCoroutine::main_func(void *arg) {
#ifdef SW_CORO_SUPPORT_BAILOUT
    zend_first_try {
#endif
        Args *php_arg = (Args *) arg;
        zend_fcall_info_cache fci_cache = *php_arg->fci_cache;
        zend_function *func = fci_cache.function_handler;
        zval *argv = php_arg->argv;
        int argc = php_arg->argc;
        PHPContext *task;
        zend_execute_data *call;
        zval _retval, *retval = &_retval;

        if (fci_cache.object) {
            GC_ADDREF(fci_cache.object);
        }

        vm_stack_init();
        call = (zend_execute_data *) (EG(vm_stack_top));
        task = (PHPContext *) EG(vm_stack_top);
        EG(vm_stack_top) = (zval *) ((char *) call + PHP_CORO_TASK_SLOT * sizeof(zval));

#if PHP_VERSION_ID < 70400
        call = zend_vm_stack_push_call_frame(
            ZEND_CALL_TOP_FUNCTION | ZEND_CALL_ALLOCATED, func, argc, fci_cache.called_scope, fci_cache.object);
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

        SW_LOOP_N(argc) {
            zval *param;
            zval *arg = &argv[i];
            if (Z_ISREF_P(arg) && !(func->common.fn_flags & ZEND_ACC_CALL_VIA_TRAMPOLINE)) {
                /* don't separate references for __call */
                arg = Z_REFVAL_P(arg);
            }
            param = ZEND_CALL_ARG(call, i + 1);
            ZVAL_COPY(param, arg);
        }

        call->symbol_table = nullptr;

        if (func->op_array.fn_flags & ZEND_ACC_CLOSURE) {
            uint32_t call_info;
            GC_ADDREF(ZEND_CLOSURE_OBJECT(func));
            call_info = ZEND_CALL_CLOSURE;
            ZEND_ADD_CALL_FLAG(call, call_info);
        }

#if defined(SW_CORO_SWAP_BAILOUT) && !defined(SW_CORO_SUPPORT_BAILOUT)
        EG(bailout) = nullptr;
#endif
        EG(current_execute_data) = call;
        EG(error_handling) = EH_NORMAL;
        EG(exception_class) = nullptr;
        EG(exception) = nullptr;
#if PHP_VERSION_ID >= 80000
        EG(jit_trace_num) = 0;
#endif

        task->output_ptr = nullptr;
#if PHP_VERSION_ID < 80100
        task->array_walk_fci = nullptr;
#endif
        task->in_silence = false;

        task->co = Coroutine::get_current();
        task->co->set_task((void *) task);
        task->defer_tasks = nullptr;
        task->pcid = task->co->get_origin_cid();
        task->context = nullptr;
        task->on_yield = nullptr;
        task->on_resume = nullptr;
        task->on_close = nullptr;
        task->enable_scheduler = true;

        save_vm_stack(task);
        record_last_msec(task);

        swoole_trace_log(SW_TRACE_COROUTINE,
                         "Create coro id: %ld, origin cid: %ld, coro total count: %zu, heap size: %zu",
                         task->co->get_cid(),
                         task->co->get_origin_cid(),
                         (uintmax_t) Coroutine::count(),
                         (uintmax_t) zend_memory_usage(0));

        if (task->pcid == -1) {
            // wait until concurrency slots are available
            while (concurrency > config.max_concurrency - 1) {
                swoole_trace_log(SW_TRACE_COROUTINE,
                                 "php_coro cid=%ld waiting for concurrency slots: max: %d, used: %d",
                                 task->co->get_cid(),
                                 config.max_concurrency,
                                 concurrency);

                swoole_event_defer(
                    [](void *data) {
                        Coroutine *co = (Coroutine *) data;
                        co->resume();
                    },
                    (void *) task->co);
                task->co->yield();
            }
            concurrency++;
        }

        if (swoole_isset_hook(SW_GLOBAL_HOOK_ON_CORO_START)) {
            swoole_call_hook(SW_GLOBAL_HOOK_ON_CORO_START, task);
        }

        if (EXPECTED(func->type == ZEND_USER_FUNCTION)) {
            ZVAL_UNDEF(retval);
            // TODO: enhancement it, separate execute data is necessary, but we lose the backtrace
            EG(current_execute_data) = nullptr;
            zend_init_func_execute_data(call, &func->op_array, retval);
            zend_execute_ex(EG(current_execute_data));
        } else { /* ZEND_INTERNAL_FUNCTION */
            ZVAL_NULL(retval);
            call->prev_execute_data = nullptr;
            call->return_value = nullptr; /* this is not a constructor call */
            execute_internal(call, retval);
            zend_vm_stack_free_args(call);
        }

        if (task->defer_tasks) {
            std::stack<zend::Function *> *tasks = task->defer_tasks;
            while (!tasks->empty()) {
                zend::Function *defer_fci = tasks->top();
                tasks->pop();
#if PHP_VERSION_ID < 80000
                defer_fci->fci.param_count = 1;
                defer_fci->fci.params = retval;
#else
                if (Z_TYPE_P(retval) != IS_UNDEF) {
                    defer_fci->fci.param_count = 1;
                    defer_fci->fci.params = retval;
                }
#endif
                if (UNEXPECTED(sw_zend_call_function_anyway(&defer_fci->fci, &defer_fci->fci_cache) != SUCCESS)) {
                    php_swoole_fatal_error(E_WARNING, "defer callback handler error");
                }
                sw_zend_fci_cache_discard(&defer_fci->fci_cache);
                efree(defer_fci);
            }
            delete task->defer_tasks;
            task->defer_tasks = nullptr;
        }

        // resources release
        if (task->context) {
            zend_object *context = task->context;
            task->context = (zend_object *) ~0;
            OBJ_RELEASE(context);
        }
        if (fci_cache.object) {
            OBJ_RELEASE(fci_cache.object);
        }
        zval_ptr_dtor(retval);
        catch_exception();
#ifdef SW_CORO_SUPPORT_BAILOUT
    }
    zend_catch {
        catch_exception();
        Coroutine::bailout([]() {
            if (sw_reactor()) {
                sw_reactor()->running = false;
                sw_reactor()->bailout = true;
            }
            zend_bailout();
        });
    }
    zend_end_try();
#endif
}

long PHPCoroutine::create(zend_fcall_info_cache *fci_cache, uint32_t argc, zval *argv) {
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
    save_task(get_context());

    return Coroutine::create(main_func, (void *) &_args);
}

void PHPCoroutine::defer(zend::Function *fci) {
    PHPContext *task = get_context();
    if (task->defer_tasks == nullptr) {
        task->defer_tasks = new std::stack<zend::Function *>;
    }
    task->defer_tasks->push(fci);
}

void php_swoole_coroutine_minit(int module_number) {
    PHPCoroutine::init();

    SW_INIT_CLASS_ENTRY_BASE(
        swoole_coroutine_util, "Swoole\\Coroutine", nullptr, "Co", swoole_coroutine_methods, nullptr);
    SW_SET_CLASS_CREATE(swoole_coroutine_util, sw_zend_create_object_deny);

    SW_INIT_CLASS_ENTRY_BASE(swoole_coroutine_iterator,
                             "Swoole\\Coroutine\\Iterator",
                             nullptr,
                             "Co\\Iterator",
                             nullptr,
                             spl_ce_ArrayIterator);
    SW_INIT_CLASS_ENTRY_BASE(
        swoole_coroutine_context, "Swoole\\Coroutine\\Context", nullptr, "Co\\Context", nullptr, spl_ce_ArrayObject);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_DEFAULT_MAX_CORO_NUM", SW_DEFAULT_MAX_CORO_NUM);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_MAX_NUM_LIMIT", Coroutine::MAX_NUM_LIMIT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_INIT", Coroutine::STATE_INIT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_WAITING", Coroutine::STATE_WAITING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_RUNNING", Coroutine::STATE_RUNNING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_END", Coroutine::STATE_END);

    // prohibit exit in coroutine
    SW_INIT_CLASS_ENTRY_EX(swoole_exit_exception,
                           "Swoole\\ExitException",
                           nullptr,
                           nullptr,
                           swoole_exit_exception_methods,
                           swoole_exception);
    zend_declare_property_long(swoole_exit_exception_ce, ZEND_STRL("flags"), 0, ZEND_ACC_PRIVATE);
    zend_declare_property_long(swoole_exit_exception_ce, ZEND_STRL("status"), 0, ZEND_ACC_PRIVATE);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_EXIT_IN_COROUTINE", SW_EXIT_IN_COROUTINE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_EXIT_IN_SERVER", SW_EXIT_IN_SERVER);
}

void php_swoole_coroutine_rinit() {
    if (SWOOLE_G(cli)) {
        ori_exit_handler = zend_get_user_opcode_handler(ZEND_EXIT);
        zend_set_user_opcode_handler(ZEND_EXIT, coro_exit_handler);

        ori_begin_silence_handler = zend_get_user_opcode_handler(ZEND_BEGIN_SILENCE);
        zend_set_user_opcode_handler(ZEND_BEGIN_SILENCE, coro_begin_silence_handler);

        ori_end_silence_handler = zend_get_user_opcode_handler(ZEND_END_SILENCE);
        zend_set_user_opcode_handler(ZEND_END_SILENCE, coro_end_silence_handler);
    }
}

void php_swoole_coroutine_rshutdown() {
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

    long cid = PHPCoroutine::create(&fci_cache, fci.param_count, fci.params);
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

    PHPContext *task =
        (PHPContext *) (EXPECTED(cid == 0) ? Coroutine::get_current_task() : Coroutine::get_task_by_cid(cid));
    if (UNEXPECTED(!task)) {
        swoole_set_last_error(SW_ERROR_CO_NOT_EXISTS);
        RETURN_NULL();
    }
    if (UNEXPECTED(task->context == (zend_object *) ~0)) {
        /* bad context (has been destroyed), see: https://github.com/swoole/swoole-src/issues/2991 */
        php_swoole_fatal_error(E_WARNING, "Context of this coroutine has been destroyed");
        RETURN_NULL();
    }
    if (UNEXPECTED(!task->context)) {
        object_init_ex(return_value, swoole_coroutine_context_ce);
        task->context = Z_OBJ_P(return_value);
    }
    GC_ADDREF(task->context);
    RETURN_OBJ(task->context);
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
    zend_long current_cid = PHPCoroutine::get_cid();
    zend_long cid = current_cid;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(cid)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    PHPContext *task = (PHPContext *) PHPCoroutine::get_context_by_cid(cid);
    if (UNEXPECTED(!task)) {
        swoole_set_last_error(SW_ERROR_CO_NOT_EXISTS);
        RETURN_FALSE;
    }

    zend_vm_stack stack = cid == current_cid ? EG(vm_stack) : task->vm_stack;
    size_t usage = 0;

    while (stack) {
        usage += (stack->end - stack->top) * sizeof(zval);
        stack = stack->prev;
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
    long cid;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &cid) == FAILURE) {
        RETURN_FALSE;
    }

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
            swoole_set_last_error(SW_ERROR_WRONG_OPERATION);
            php_swoole_error(E_WARNING, "can not join self");
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
    long cid;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &cid) == FAILURE) {
        RETURN_FALSE;
    }

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
        PHPContext *task = (PHPContext *) PHPCoroutine::get_context_by_cid(cid);
        if (UNEXPECTED(!task)) {
            swoole_set_last_error(SW_ERROR_CO_NOT_EXISTS);
            RETURN_FALSE;
        }
        zend_execute_data *ex_backup = EG(current_execute_data);
        EG(current_execute_data) = task->execute_data;
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
