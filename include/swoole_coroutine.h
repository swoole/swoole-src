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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole_api.h"
#include "swoole_string.h"
#include "swoole_socket.h"
#include "swoole_reactor.h"
#include "swoole_timer.h"
#include "swoole_async.h"

#include "swoole_coroutine_context.h"

#include <limits.h>

#include <functional>
#include <string>
#include <unordered_map>

namespace swoole {
class Coroutine {
  public:
    constexpr static int STACK_ALIGNED_SIZE = (4 * 1024);
    constexpr static int MIN_STACK_SIZE = (64 * 1024);
    constexpr static int MAX_STACK_SIZE = (16 * 1024 * 1024);
    constexpr static long MAX_NUM_LIMIT = LONG_MAX;

    enum State {
        STATE_INIT = 0,
        STATE_WAITING,
        STATE_RUNNING,
        STATE_END,
    };

    enum Error {
        ERR_END = 0,
        ERR_LIMIT = -1,
        ERR_INVALID = -2,
    };

    enum ResumeCode {
        RC_OK = 0,
        RC_TIMEDOUT = -1,
        RC_CANCELED = -2,
    };

    typedef void (*SwapCallback)(void *);
    typedef std::function<void(void)> BailoutCallback;
    typedef std::function<bool(swoole::Coroutine*)> CancelFunc;

    void resume();
    void yield();
    void yield(CancelFunc *cancel_fn);
    bool cancel();

    bool yield_ex(double timeout = -1);

    inline enum State get_state() const {
        return state;
    }

    inline long get_init_msec() const  {
        return init_msec;
    }

    inline long get_cid() const {
        return cid;
    }

    inline Coroutine *get_origin() {
        return origin;
    }

    inline long get_origin_cid() {
        return sw_likely(origin) ? origin->get_cid() : -1;
    }

    inline void *get_task() {
        return task;
    }

    inline bool is_end() {
        return ctx.is_end();
    }

    bool is_canceled() const {
        return resume_code_ == RC_CANCELED;
    }

    bool is_timedout() const {
        return resume_code_ == RC_TIMEDOUT;
    }

    bool is_suspending() const {
        return state == STATE_WAITING;
    }

    inline void set_task(void *_task) {
        task = _task;
    }

    void set_cancel_fn(CancelFunc *cancel_fn) {
        cancel_fn_ = cancel_fn;
    }

    static std::unordered_map<long, Coroutine *> coroutines;

    static void set_on_yield(SwapCallback func);
    static void set_on_resume(SwapCallback func);
    static void set_on_close(SwapCallback func);
    static void bailout(BailoutCallback func);

    static inline long create(const CoroutineFunc &fn, void *args = nullptr) {
#ifdef SW_USE_THREAD_CONTEXT
        try {
            return (new Coroutine(fn, args))->run();
        } catch (const std::system_error& e) {
            swoole_set_last_error(e.code().value());
            swoole_warning("failed to create coroutine, Error: %s[%d]", e.what(), swoole_get_last_error());
            return -1;
        }
#else
        return (new Coroutine(fn, args))->run();
#endif
    }

    static void activate();
    static void deactivate();

    static inline Coroutine *get_current() {
        return current;
    }

    static inline Coroutine *get_current_safe() {
        if (sw_unlikely(!current)) {
            swoole_fatal_error(SW_ERROR_CO_OUT_OF_COROUTINE, "API must be called in the coroutine");
        }
        return current;
    }

    static inline void *get_current_task() {
        return sw_likely(current) ? current->get_task() : nullptr;
    }

    static inline long get_current_cid() {
        return sw_likely(current) ? current->get_cid() : -1;
    }

    static inline Coroutine *get_by_cid(long cid) {
        auto i = coroutines.find(cid);
        return sw_likely(i != coroutines.end()) ? i->second : nullptr;
    }

    static inline void *get_task_by_cid(long cid) {
        Coroutine *co = get_by_cid(cid);
        return sw_likely(co) ? co->get_task() : nullptr;
    }

    static inline size_t get_stack_size() {
        return stack_size;
    }

    static inline void set_stack_size(size_t size) {
        stack_size = SW_MEM_ALIGNED_SIZE_EX(SW_MAX(MIN_STACK_SIZE, SW_MIN(size, MAX_STACK_SIZE)), STACK_ALIGNED_SIZE);
    }

    static inline long get_last_cid() {
        return last_cid;
    }

    static inline size_t count() {
        return coroutines.size();
    }

    static inline uint64_t get_peak_num() {
        return peak_num;
    }

    static inline long get_elapsed(long cid) {
        Coroutine *co = cid == 0 ? get_current() : get_by_cid(cid);
        return sw_likely(co) ? Timer::get_absolute_msec() - co->get_init_msec() : -1;
    }

    static void print_list();

  protected:
    static Coroutine *current;
    static long last_cid;
    static uint64_t peak_num;
    static size_t stack_size;
    static SwapCallback on_yield;   /* before yield */
    static SwapCallback on_resume;  /* before resume */
    static SwapCallback on_close;   /* before close */
    static BailoutCallback on_bailout; /* when bailout */
    static bool activated;

    enum State state = STATE_INIT;
    enum ResumeCode resume_code_ = RC_OK;
    long cid;
    long init_msec = Timer::get_absolute_msec();
    void *task = nullptr;
    coroutine::Context ctx;
    Coroutine *origin = nullptr;
    CancelFunc *cancel_fn_ = nullptr;

    Coroutine(const CoroutineFunc &fn, void *private_data) : ctx(stack_size, fn, private_data) {
        cid = ++last_cid;
        coroutines[cid] = this;
        if (sw_unlikely(count() > peak_num)) {
            peak_num = count();
        }
    }

    inline long run() {
        long cid = this->cid;
        origin = current;
        current = this;
        ctx.swap_in();
        check_end();
        return cid;
    }

    inline void check_end() {
        if (ctx.is_end()) {
            close();
        } else if (sw_unlikely(on_bailout)) {
            SW_ASSERT(current == nullptr);
            on_bailout();
            exit(SW_CORO_BAILOUT_EXIT_CODE);
        }
    }

    void close();
};
//-------------------------------------------------------------------------------
namespace coroutine {
bool async(async::Handler handler, AsyncEvent &event, double timeout = -1);
bool async(const std::function<void(void)> &fn, double timeout = -1);
bool run(const CoroutineFunc &fn, void *arg = nullptr);
}  // namespace coroutine
//-------------------------------------------------------------------------------
}  // namespace swoole

/**
 * for gdb
 */
swoole::Coroutine *swoole_coroutine_iterator_each();
void swoole_coroutine_iterator_reset();
swoole::Coroutine *swoole_coroutine_get(long cid);
size_t swoole_coroutine_count();
