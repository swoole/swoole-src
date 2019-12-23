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

#include "swoole_api.h"
#include "context.h"
#include "async.h"

#include <limits.h>

#include <string>
#include <unordered_map>

#define SW_CORO_STACK_ALIGNED_SIZE (4 * 1024)
#define SW_CORO_MIN_STACK_SIZE     (256  * 1024)
#define SW_CORO_MAX_STACK_SIZE     (16 * 1024 * 1024)
#define SW_CORO_MAX_NUM_LIMIT      LONG_MAX

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

typedef void (*sw_coro_on_swap_t)(void*);
typedef void (*sw_coro_bailout_t)();

namespace swoole
{
struct socket_poll_fd
{
    int16_t events;
    int16_t revents;
    void *ptr;
    swSocket *socket;

    socket_poll_fd(int16_t _event, void *_ptr)
    {
        events = _event;
        ptr = _ptr;
        revents = 0;
        socket = new swSocket;
    }
};

class Coroutine
{
public:
    void resume();
    void yield();

    void resume_naked();
    void yield_naked();

    inline sw_coro_state get_state()
    {
        return state;
    }

    inline long get_cid()
    {
        return cid;
    }

    inline Coroutine* get_origin()
    {
        return origin;
    }

    inline long get_origin_cid()
    {
        return sw_likely(origin) ? origin->get_cid() : -1;
    }

    inline void* get_task()
    {
        return task;
    }

    inline bool is_end()
    {
        return ctx.is_end();
    }

    inline void set_task(void *_task)
    {
        task = _task;
    }

    static std::unordered_map<long, Coroutine*> coroutines;

    static void set_on_yield(sw_coro_on_swap_t func);
    static void set_on_resume(sw_coro_on_swap_t func);
    static void set_on_close(sw_coro_on_swap_t func);
    static void bailout(sw_coro_bailout_t func);

    static inline long create(coroutine_func_t fn, void* args = nullptr)
    {
        return (new Coroutine(fn, args))->run();
    }

    static inline Coroutine* get_current()
    {
        return current;
    }

    static inline Coroutine* get_current_safe()
    {
        if (sw_unlikely(!current))
        {
            swFatalError(SW_ERROR_CO_OUT_OF_COROUTINE, "API must be called in the coroutine");
        }
        return current;
    }

    static inline void* get_current_task()
    {
        return sw_likely(current) ? current->get_task() : nullptr;
    }

    static inline long get_current_cid()
    {
        return sw_likely(current) ? current->get_cid() : -1;
    }

    static inline Coroutine* get_by_cid(long cid)
    {
        auto i = coroutines.find(cid);
        return sw_likely(i != coroutines.end()) ? i->second : nullptr;
    }

    static inline void* get_task_by_cid(long cid)
    {
        Coroutine *co = get_by_cid(cid);
        return sw_likely(co) ? co->get_task() : nullptr;
    }

    static inline size_t get_stack_size()
    {
        return stack_size;
    }

    static inline void set_stack_size(size_t size)
    {
        stack_size = SW_MEM_ALIGNED_SIZE_EX(SW_MAX(SW_CORO_MIN_STACK_SIZE, SW_MIN(size, SW_CORO_MAX_STACK_SIZE)), SW_CORO_STACK_ALIGNED_SIZE);
    }

    static inline long get_last_cid()
    {
        return last_cid;
    }

    static inline size_t count()
    {
        return coroutines.size();
    }

    static inline uint64_t get_peak_num()
    {
        return peak_num;
    }

    static void print_list();

protected:
    static Coroutine* current;
    static long last_cid;
    static uint64_t peak_num;
    static size_t stack_size;
    static sw_coro_on_swap_t on_yield;   /* before yield */
    static sw_coro_on_swap_t on_resume;  /* before resume */
    static sw_coro_on_swap_t on_close;   /* before close */
    static sw_coro_bailout_t on_bailout; /* when bailout */

    sw_coro_state state = SW_CORO_INIT;
    long cid;
    void *task = nullptr;
    Context ctx;
    Coroutine *origin;

    Coroutine(coroutine_func_t fn, void *private_data) :
            ctx(stack_size, fn, private_data)
    {
        cid = ++last_cid;
        coroutines[cid] = this;
        if (sw_unlikely(count() > peak_num))
        {
            peak_num = count();
        }
    }

    inline long run()
    {
        long cid = this->cid;
        origin = current;
        current = this;
        ctx.swap_in();
        check_end();
        return cid;
    }

    inline void check_end()
    {
        if (ctx.is_end())
        {
            close();
        }
        else if (sw_unlikely(on_bailout))
        {
            SW_ASSERT(current == nullptr);
            on_bailout();
            // expect that never here
            exit(1);
        }
    }

    void close();
};
//-------------------------------------------------------------------------------
namespace coroutine
{
bool async(swAio_handler handler, swAio_event &event, double timeout = -1);
}
//-------------------------------------------------------------------------------
}

/**
 * for gdb
 */
swoole::Coroutine* swoole_coro_iterator_each();
void swoole_coro_iterator_reset();
swoole::Coroutine* swoole_coro_get(long cid);
size_t swoole_coro_count();
