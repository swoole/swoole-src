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

#include "coroutine_cxx_api.h"
#include "zend_vm.h"
#include "zend_closures.h"

#include <stack>

#define SW_DEFAULT_MAX_CORO_NUM              100000
#define SW_DEFAULT_PHP_STACK_PAGE_SIZE       8192

#define SWOG ((zend_output_globals *) &OG(handlers))

enum sw_coro_hook_type
{
    SW_HOOK_TCP               = 1u << 1,
    SW_HOOK_UDP               = 1u << 2,
    SW_HOOK_UNIX              = 1u << 3,
    SW_HOOK_UDG               = 1u << 4,
    SW_HOOK_SSL               = 1u << 5,
    SW_HOOK_TLS               = 1u << 6,
    SW_HOOK_STREAM_FUNCTION   = 1u << 7,
    SW_HOOK_FILE              = 1u << 8,
    SW_HOOK_SLEEP             = 1u << 9,
    SW_HOOK_PROC              = 1u << 10,
    SW_HOOK_CURL              = 1u << 28,
    SW_HOOK_BLOCKING_FUNCTION = 1u << 30,

    SW_HOOK_ALL               = 0x7fffffff ^ SW_HOOK_CURL /* TODO: remove it */
};

struct php_coro_task
{
    JMP_BUF *bailout;
    zval *vm_stack_top;
    zval *vm_stack_end;
    zend_vm_stack vm_stack;
    size_t vm_stack_page_size;
    zend_execute_data *execute_data;
    zend_error_handling_t error_handling;
    zend_class_entry *exception_class;
    zend_object *exception;
    zend_output_globals *output_ptr;
    swoole::Coroutine *co;
    std::stack<php_swoole_fci *> *defer_tasks;
    long pcid;
    zend_object *context;
    int64_t last_msec;
    zend_bool enable_scheduler;
};

struct php_coro_args
{
    zend_fcall_info_cache *fci_cache;
    zval *argv;
    uint32_t argc;
};

// TODO: remove php coro context
struct php_coro_context
{
    zval coro_params;
    zval *current_coro_return_value_ptr;
    void *private_data;
    swTimer_node *timer;
    php_coro_task *current_task;
};

PHP_METHOD(swoole_coroutine_scheduler, set);

namespace swoole
{

namespace coroutine
{
struct Config
{
    uint64_t max_num;
    long hook_flags;
    bool enable_preemptive_scheduler;
};
}

class PHPCoroutine
{
public:
    static const uint8_t MAX_EXEC_MSEC = 10;
    static coroutine::Config config;

    static void init();
    static void deactivate(void *ptr);
    static void shutdown();
    static long create(zend_fcall_info_cache *fci_cache, uint32_t argc, zval *argv);
    static void defer(php_swoole_fci *fci);

    static bool enable_hook(int flags);
    static bool disable_hook();

    static void interrupt_thread_stop();

    // TODO: remove old coro APIs (Manual)
    static void yield_m(zval *return_value, php_coro_context *sw_php_context);
    static int resume_m(php_coro_context *sw_current_context, zval *retval, zval *coro_retval);

    static inline long get_cid()
    {
        return sw_likely(active) ? Coroutine::get_current_cid() : -1;
    }

    static inline long get_pcid(long cid = 0)
    {
        php_coro_task *task = cid == 0 ? get_task() : get_task_by_cid(cid);
        return sw_likely(task) ? task->pcid : 0;
    }

    static inline php_coro_task* get_task()
    {
        php_coro_task *task = (php_coro_task *) Coroutine::get_current_task();
        return task ? task : &main_task;
    }

    static inline php_coro_task* get_origin_task(php_coro_task *task)
    {
        Coroutine *co = task->co->get_origin();
        return co ? (php_coro_task *) co->get_task() : &main_task;
    }

    static inline php_coro_task* get_task_by_cid(long cid)
    {
        return cid == -1 ? &main_task : (php_coro_task *) Coroutine::get_task_by_cid(cid);
    }

    static inline uint64_t get_max_num()
    {
        return config.max_num;
    }

    static inline void set_max_num(uint64_t n)
    {
        config.max_num = n;
    }

    static inline bool is_schedulable(php_coro_task *task)
    {
        return task->enable_scheduler && (swTimer_get_absolute_msec() - task->last_msec > MAX_EXEC_MSEC);
    }

    static inline bool enable_scheduler()
    {
        php_coro_task *task = (php_coro_task *) Coroutine::get_current_task();
        if (task && task->enable_scheduler == 0)
        {
            task->enable_scheduler = 1;
            return true;
        }
        return false;
    }

    static inline bool disable_scheduler()
    {
        php_coro_task *task = (php_coro_task *) Coroutine::get_current_task();
        if (task && task->enable_scheduler == 1)
        {
            task->enable_scheduler = 0;
            return true;
        }
        return false;
    }

protected:
    static bool active;
    static php_coro_task main_task;

    static bool interrupt_thread_running;
    static pthread_t interrupt_thread_id;

    static void activate();
    static void error(int type, const char *error_filename, const uint32_t error_lineno, const char *format, va_list args);

    static inline void vm_stack_init(void);
    static inline void vm_stack_destroy(void);
    static inline void save_vm_stack(php_coro_task *task);
    static inline void restore_vm_stack(php_coro_task *task);
    static inline void save_og(php_coro_task *task);
    static inline void restore_og(php_coro_task *task);
    static inline void save_task(php_coro_task *task);
    static inline void restore_task(php_coro_task *task);
    static void on_yield(void *arg);
    static void on_resume(void *arg);
    static void on_close(void *arg);
    static void main_func(void *arg);

    static void interrupt_thread_start();
    static void interrupt_thread_loop();
    static inline void record_last_msec(php_coro_task *task)
    {
        if (interrupt_thread_running)
        {
            task->last_msec = swTimer_get_absolute_msec();
        }
    }

    static bool inject_function();
};
}

