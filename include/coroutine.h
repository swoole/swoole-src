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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"
#include "context.h"

#include <string>
#include <unordered_map>

#define SW_CORO_STACK_ALIGNED_SIZE (4 * 1024)
#define SW_CORO_MAX_STACK_SIZE     (16 * 1024 * 1024)

// TODO: remove it
typedef enum
{
    SW_CORO_ERR_END = 0,
    SW_CORO_ERR_LIMIT = -1,
    SW_CORO_ERR_INVALID = -2,
} sw_coro_error;

typedef enum
{
    SW_CORO_INIT = 0,
    SW_CORO_WAITING,
    SW_CORO_RUNNING,
    SW_CORO_END,
} sw_coro_state;

typedef void (*coro_php_create_t)();
typedef void (*coro_php_yield_t)(void*);
typedef void (*coro_php_resume_t)(void*);
typedef void (*coro_php_close_t)(void*);

namespace swoole
{
void set_dns_cache_expire(time_t expire);
void set_dns_cache_capacity(size_t capacity);
void clear_dns_cache();

class Coroutine
{
public:
    void resume();
    void yield();

    void resume_naked();
    void yield_naked();

    void close();

    inline sw_coro_state get_state()
    {
        return state;
    }

    inline long get_cid()
    {
        return cid;
    }

    inline void* get_task()
    {
        return task;
    }

    inline void set_task(void *_task)
    {
        task = _task;
    }

    static std::unordered_map<long, Coroutine*> coroutines;

    static Coroutine* get_current();
    static void* get_current_task();
    static long get_current_cid();
    static Coroutine* get_by_cid(long cid);
    static void* get_task_by_cid(long cid);
    static void print_list();

    static long create(coroutine_func_t fn, void* args = nullptr);
    static int sleep(double sec);
    static swString* read_file(const char *file, int lock);
    static ssize_t write_file(const char *file, char *buf, size_t length, int lock, int flags);
    static std::string gethostbyname(const std::string &hostname, int domain, double timeout = -1);

    static void set_on_yield(coro_php_yield_t func);
    static void set_on_resume(coro_php_resume_t func);
    static void set_on_close(coro_php_close_t func);

    static inline size_t get_stack_size()
    {
        return stack_size;
    }

    static inline void set_stack_size(size_t size)
    {
        stack_size = SW_MEM_ALIGNED_SIZE_EX(MIN(size, SW_CORO_MAX_STACK_SIZE), SW_CORO_STACK_ALIGNED_SIZE);
    }

#ifdef SW_LOG_TRACE_OPEN
    static inline long get_cid(Coroutine* co)
    {
        return co ? co->get_cid() : -1;
    }
#endif

    static inline long get_last_cid()
    {
        return last_cid;
    }

    static inline size_t count()
    {
        return coroutines.size();
    }

    static uint64_t get_peak_num()
    {
        return peak_num;
    }

protected:
    static size_t stack_size;
    static size_t call_stack_size;
    static Coroutine* call_stack[SW_MAX_CORO_NESTING_LEVEL];
    static long last_cid;
    static uint64_t peak_num;
    static coro_php_yield_t  on_yield;  /* before php yield coro */
    static coro_php_resume_t on_resume; /* before php resume coro */
    static coro_php_close_t  on_close;  /* before php close coro */

    sw_coro_state state = SW_CORO_INIT;
    long cid;
    void *task = nullptr;
    Context ctx;

    Coroutine(coroutine_func_t fn, void *private_data) :
            ctx(stack_size, fn, private_data)
    {
        cid = ++last_cid;
        coroutines[cid] = this;
        call_stack[call_stack_size++] = this;
        if (count() > peak_num)
        {
            peak_num = count();
        }
    }

    inline long run()
    {
        long cid = this->cid;
        ctx.SwapIn();
        if (ctx.end)
        {
            close();
        }
        return cid;
    }
};
}

/**
 * for gdb
 */
swoole::Coroutine* swoole_coro_iterator_each();
void swoole_coro_iterator_reset();
swoole::Coroutine* swoole_coro_get(long cid);
size_t swoole_coro_count();
