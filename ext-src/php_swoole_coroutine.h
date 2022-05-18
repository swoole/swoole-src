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
#if PHP_VERSION_ID >= 80000
    uint32_t jit_trace_num;
#endif
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
    };

    struct Config {
        uint64_t max_num;
        uint32_t max_concurrency;
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
#ifdef SW_USE_CURL
        HOOK_ALL               = 0x7fffffff ^ HOOK_CURL,
#else
        HOOK_ALL               = 0x7fffffff ^ HOOK_NATIVE_CURL,
#endif
    };

    static const uint8_t MAX_EXEC_MSEC = 10;
    static void init();
    static void shutdown();
    static long create(zend_fcall_info_cache *fci_cache, uint32_t argc, zval *argv);
    static void defer(zend::Function *fci);
    static void deadlock_check();
    static bool enable_hook(uint32_t flags);
    static bool disable_hook();
    static void disable_unsafe_function();
    static void enable_unsafe_function();
    static void error_cb(int type, error_filename_t *error_filename, const uint32_t error_lineno, ZEND_ERROR_CB_LAST_ARG_D);
    static void interrupt_thread_stop();

    static inline long get_cid() {
        return sw_likely(activated) ? Coroutine::get_current_cid() : -1;
    }

    static inline long get_pcid(long cid = 0) {
        PHPContext *task = cid == 0 ? get_context() : get_context_by_cid(cid);
        return sw_likely(task) ? task->pcid : 0;
    }

    static inline long get_elapsed(long cid = 0) {
        return sw_likely(activated) ? Coroutine::get_elapsed(cid) : -1;
    }

    static inline PHPContext *get_context() {
        PHPContext *task = (PHPContext *) Coroutine::get_current_task();
        return task ? task : &main_task;
    }

    static inline PHPContext *get_origin_context(PHPContext *task) {
        Coroutine *co = task->co->get_origin();
        return co ? (PHPContext *) co->get_task() : &main_task;
    }

    static inline PHPContext *get_context_by_cid(long cid) {
        return cid == -1 ? &main_task : (PHPContext *) Coroutine::get_task_by_cid(cid);
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

    static inline bool is_schedulable(PHPContext *task) {
        return task->enable_scheduler && (Timer::get_absolute_msec() - task->last_msec > MAX_EXEC_MSEC);
    }

    static inline bool enable_scheduler() {
        PHPContext *task = (PHPContext *) Coroutine::get_current_task();
        if (task && !task->enable_scheduler) {
            task->enable_scheduler = true;
            return true;
        }
        return false;
    }

    static inline bool disable_scheduler() {
        PHPContext *task = (PHPContext *) Coroutine::get_current_task();
        if (task && task->enable_scheduler) {
            task->enable_scheduler = false;
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

    static inline void set_max_concurrency(uint32_t value) {
        config.max_concurrency = value;
    }

    static inline bool is_activated() {
        return activated;
    }

  protected:
    static bool activated;
    static PHPContext main_task;
    static Config config;
    static uint32_t concurrency;

    static bool interrupt_thread_running;
    static std::thread interrupt_thread;

    static void activate();
    static void deactivate(void *ptr);

    static void vm_stack_init(void);
    static void vm_stack_destroy(void);
    static void save_vm_stack(PHPContext *task);
    static void restore_vm_stack(PHPContext *task);
    static void save_og(PHPContext *task);
    static void restore_og(PHPContext *task);
    static void save_task(PHPContext *task);
    static void restore_task(PHPContext *task);
    static void catch_exception();
    static void on_yield(void *arg);
    static void on_resume(void *arg);
    static void on_close(void *arg);
    static void main_func(void *arg);

    static void interrupt_thread_start();
    static void record_last_msec(PHPContext *task) {
        if (interrupt_thread_running) {
            task->last_msec = Timer::get_absolute_msec();
        }
    }
};
}  // namespace swoole

/**
 * for gdb
 */
zend_executor_globals *php_swoole_get_executor_globals();
