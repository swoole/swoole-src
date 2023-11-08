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

#pragma once

#include "swoole_coroutine.h"
#include "swoole_coroutine_socket.h"
#include "swoole_coroutine_system.h"
#include "zend_vm.h"
#include "zend_closures.h"

#if PHP_VERSION_ID >= 80100
#define SWOOLE_COROUTINE_MOCK_FIBER_CONTEXT 1
#include "zend_fibers.h"
#include "zend_observer.h"
#endif

#include <stack>
#include <thread>

#define SW_DEFAULT_MAX_CORO_NUM 100000
#define SW_DEFAULT_PHP_STACK_PAGE_SIZE 8192

#define SWOG ((zend_output_globals *) &OG(handlers))

SW_EXTERN_C_BEGIN
PHP_METHOD(swoole_coroutine_scheduler, set);
PHP_METHOD(swoole_coroutine_scheduler, getOptions);
SW_EXTERN_C_END

namespace zend {
struct Function;
}

namespace swoole {

struct PHPContext {
    typedef std::function<void(PHPContext *)> SwapCallback;

    JMP_BUF *bailout;
    zval *vm_stack_top;
    zval *vm_stack_end;
    zend_vm_stack vm_stack;
    size_t vm_stack_page_size;
    zend_execute_data *execute_data;
    uint32_t jit_trace_num;
    zend_error_handling_t error_handling;
    zend_class_entry *exception_class;
    zend_object *exception;
    zend_output_globals *output_ptr;
#if PHP_VERSION_ID < 80100
    /* for array_walk non-reentrancy */
    zend::Function *array_walk_fci;
#endif
    /* for error control `@` */
    bool in_silence;
    bool enable_scheduler;
    int ori_error_reporting;
    int tmp_error_reporting;
    Coroutine *co;
    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;
    zval return_value;
#ifdef SWOOLE_COROUTINE_MOCK_FIBER_CONTEXT
    zend_fiber_context *fiber_context;
    bool fiber_init_notified;
#endif
#ifdef ZEND_CHECK_STACK_LIMIT
	void *stack_base;
	void *stack_limit;
#endif
    std::stack<zend::Function *> *defer_tasks;
    SwapCallback *on_yield;
    SwapCallback *on_resume;
    SwapCallback *on_close;
    long pcid;
    zend_object *context;
    int64_t last_msec;
};

class PHPCoroutine {
  public:
    struct Args {
        zend_fcall_info_cache *fci_cache;
        zval *argv;
        uint32_t argc;
        zval *callable;
    };

    struct Config {
        uint64_t max_num;
        uint32_t hook_flags;
        bool enable_preemptive_scheduler;
        bool enable_deadlock_check;
    };

    static zend_array *options;

    enum HookType {
        HOOK_NONE              = 0,
        HOOK_TCP               = 1u << 1,
        HOOK_UDP               = 1u << 2,
        HOOK_UNIX              = 1u << 3,
        HOOK_UDG               = 1u << 4,
        HOOK_SSL               = 1u << 5,
        HOOK_TLS               = 1u << 6,
        HOOK_STREAM_FUNCTION   = 1u << 7,
        HOOK_FILE              = 1u << 8,
        HOOK_SLEEP             = 1u << 9,
        HOOK_PROC              = 1u << 10,
        HOOK_CURL              = 1u << 11,
        HOOK_NATIVE_CURL       = 1u << 12,
        HOOK_BLOCKING_FUNCTION = 1u << 13,
        HOOK_SOCKETS           = 1u << 14,
        HOOK_STDIO             = 1u << 15,
        HOOK_PDO_PGSQL         = 1u << 16,
        HOOK_PDO_ODBC          = 1u << 17,
        HOOK_PDO_ORACLE        = 1u << 18,
        HOOK_PDO_SQLITE        = 1u << 19,
#ifdef SW_USE_CURL
        HOOK_ALL               = 0x7fffffff ^ HOOK_CURL,
#else
        HOOK_ALL               = 0x7fffffff ^ HOOK_NATIVE_CURL,
#endif
    };

    static const uint8_t MAX_EXEC_MSEC = 10;
    static void shutdown();
    static long create(zend_fcall_info_cache *fci_cache, uint32_t argc, zval *argv, zval *callable);
    static PHPContext *create_context(Args *args);
    static void defer(zend::Function *fci);
    static void deadlock_check();
    static bool enable_hook(uint32_t flags);
    static bool disable_hook();
    static void disable_unsafe_function();
    static void enable_unsafe_function();
    static void interrupt_thread_stop();

    static inline long get_cid() {
        return sw_likely(activated) ? Coroutine::get_current_cid() : -1;
    }

    static inline long get_pcid(long cid = 0) {
        PHPContext *ctx = cid == 0 ? get_context() : get_context_by_cid(cid);
        return sw_likely(ctx) ? ctx->pcid : 0;
    }

    static inline long get_elapsed(long cid = 0) {
        return sw_likely(activated) ? Coroutine::get_elapsed(cid) : -1;
    }

    static inline PHPContext *get_context() {
        PHPContext *ctx = (PHPContext *) Coroutine::get_current_task();
        return ctx ? ctx : &main_context;
    }

    static inline PHPContext *get_origin_context(PHPContext *ctx) {
        Coroutine *co = ctx->co->get_origin();
        return co ? (PHPContext *) co->get_task() : &main_context;
    }

    static inline PHPContext *get_context_by_cid(long cid) {
        return cid == -1 ? &main_context : (PHPContext *) Coroutine::get_task_by_cid(cid);
    }

    static inline ssize_t get_stack_usage(long cid) {
        zend_long current_cid = PHPCoroutine::get_cid();
        if (cid == 0) {
            cid = current_cid;
        }
        PHPContext *ctx = (PHPContext *) PHPCoroutine::get_context_by_cid(cid);
        if (UNEXPECTED(!ctx)) {
            swoole_set_last_error(SW_ERROR_CO_NOT_EXISTS);
            return -1;
        }
        zend_vm_stack stack = cid == current_cid ? EG(vm_stack) : ctx->vm_stack;
        size_t usage = 0;

        while (stack) {
            usage += (stack->end - stack->top) * sizeof(zval);
            stack = stack->prev;
        }
        return usage;
    }

    static inline uint64_t get_max_num() {
        return config.max_num;
    }

    static inline void set_max_num(uint64_t n) {
        config.max_num = n;
    }

    static inline void set_deadlock_check(bool value = true) {
        config.enable_deadlock_check = value;
    }

    static inline bool is_schedulable(PHPContext *ctx) {
        return ctx->enable_scheduler && (Timer::get_absolute_msec() - ctx->last_msec > MAX_EXEC_MSEC);
    }

    static inline bool enable_scheduler() {
        PHPContext *ctx = (PHPContext *) Coroutine::get_current_task();
        if (ctx && !ctx->enable_scheduler) {
            ctx->enable_scheduler = true;
            return true;
        }
        return false;
    }

    static inline bool disable_scheduler() {
        PHPContext *ctx = (PHPContext *) Coroutine::get_current_task();
        if (ctx && ctx->enable_scheduler) {
            ctx->enable_scheduler = false;
            return true;
        }
        return false;
    }

    static void set_hook_flags(uint32_t flags);

    static inline uint32_t get_hook_flags() {
        return config.hook_flags;
    }

    static inline void enable_preemptive_scheduler(bool value) {
        config.enable_preemptive_scheduler = value;
    }

    static inline bool is_activated() {
        return activated;
    }

    static inline long get_execute_time(long cid = 0) {
        return sw_likely(activated) ? Coroutine::get_execute_time(cid) : -1;
    }

    static inline void init_main_context() {
        main_context.co = Coroutine::init_main_coroutine();
#ifdef SWOOLE_COROUTINE_MOCK_FIBER_CONTEXT
        main_context.fiber_context = EG(main_fiber_context);
        main_context.fiber_init_notified = true;
#endif
        save_context(&main_context);
    }

  protected:
    static bool activated;
    static PHPContext main_context;
    static Config config;

    static bool interrupt_thread_running;
    static std::thread interrupt_thread;

    static void activate();
    static void deactivate(void *ptr);

    static void save_vm_stack(PHPContext *ctx);
    static void restore_vm_stack(PHPContext *ctx);
    static void save_og(PHPContext *ctx);
    static void restore_og(PHPContext *ctx);
    static void save_context(PHPContext *ctx);
    static void restore_context(PHPContext *ctx);
    static void destroy_context(PHPContext *ctx);
    static bool catch_exception();
    static void bailout();
    static void on_yield(void *arg);
    static void on_resume(void *arg);
    static void on_close(void *arg);
    static void main_func(void *arg);
#ifdef SWOOLE_COROUTINE_MOCK_FIBER_CONTEXT
    static zend_fiber_status get_fiber_status(PHPContext *ctx);
    static void fiber_context_init(PHPContext *ctx);
    static void fiber_context_try_init(PHPContext *ctx);
    static void fiber_context_destroy(PHPContext *ctx);
    static void fiber_context_try_destroy(PHPContext *ctx);
    static void fiber_context_switch_notify(PHPContext *from, PHPContext *to);
    static void fiber_context_switch_try_notify(PHPContext *from, PHPContext *to);
#endif
#ifdef ZEND_CHECK_STACK_LIMIT
    static void* stack_limit(PHPContext *ctx);
    static void* stack_base(PHPContext *ctx);
#endif
    static void interrupt_thread_start();
    static void record_last_msec(PHPContext *ctx) {
        if (interrupt_thread_running) {
            ctx->last_msec = Timer::get_absolute_msec();
        }
    }
};
}  // namespace swoole

/**
 * for gdb
 */
zend_executor_globals *php_swoole_get_executor_globals();
