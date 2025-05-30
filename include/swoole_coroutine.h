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
#include "swoole_util.h"

#include "swoole_coroutine_context.h"

#include <climits>

#include <functional>
#include <string>
#include <unordered_map>
#ifdef SW_USE_THREAD_CONTEXT
#include <system_error>
#endif

typedef std::chrono::microseconds seconds_type;

#ifdef SW_CORO_TIME
#define CALC_EXECUTE_USEC(yield_coroutine, resume_coroutine) calc_execute_usec(yield_coroutine, resume_coroutine)
#else
#define CALC_EXECUTE_USEC(yield_coroutine, resume_coroutine)
#endif

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
    typedef std::function<bool(swoole::Coroutine *)> CancelFunc;

    void resume();
    void yield();
    void yield(CancelFunc *cancel_fn);
    bool cancel();

    bool yield_ex(double timeout = -1);

    enum State get_state() const {
        return state;
    }

    long get_init_msec() const {
        return init_msec;
    }

    long get_cid() const {
        return cid;
    }

    Coroutine *get_origin() {
        return origin;
    }

    long get_origin_cid() {
        return sw_likely(origin) ? origin->get_cid() : -1;
    }

    void *get_task() {
        return task;
    }

    bool is_end() {
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

    void set_task(void *_task) {
        task = _task;
    }

    void set_cancel_fn(CancelFunc *cancel_fn) {
        cancel_fn_ = cancel_fn;
    }

    long get_execute_usec() const {
        return time<seconds_type>(true) - switch_usec + execute_usec;
    }

    coroutine::Context &get_ctx() {
        return ctx;
    }

    static SW_THREAD_LOCAL std::unordered_map<long, Coroutine *> coroutines;

    static void set_on_yield(SwapCallback func);
    static void set_on_resume(SwapCallback func);
    static void set_on_close(SwapCallback func);
    static void bailout(const BailoutCallback &func);

    static inline long create(const CoroutineFunc &fn, void *args = nullptr) {
#ifdef SW_USE_THREAD_CONTEXT
        try {
            return (new Coroutine(fn, args))->run();
        } catch (const std::system_error &e) {
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

    static inline long get_execute_time(long cid) {
        Coroutine *co = cid == 0 ? get_current() : get_by_cid(cid);
        return sw_likely(co) ? co->get_execute_usec() : -1;
    }

#ifdef SW_CORO_TIME
    static void calc_execute_usec(Coroutine *yield_coroutine, Coroutine *resume_coroutine);
#endif
    static void print_list();

  protected:
    static SW_THREAD_LOCAL Coroutine *current;
    static SW_THREAD_LOCAL long last_cid;
    static SW_THREAD_LOCAL uint64_t peak_num;
    static SW_THREAD_LOCAL size_t stack_size;
    static SW_THREAD_LOCAL SwapCallback on_yield;      /* before yield */
    static SW_THREAD_LOCAL SwapCallback on_resume;     /* before resume */
    static SW_THREAD_LOCAL SwapCallback on_close;      /* before close */
    static SW_THREAD_LOCAL BailoutCallback on_bailout; /* when bailout */
    static SW_THREAD_LOCAL bool activated;

    enum State state = STATE_INIT;
    enum ResumeCode resume_code_ = RC_OK;
    long cid;
    long init_msec = Timer::get_absolute_msec();
    long switch_usec = time<seconds_type>(true);
    long execute_usec = 0;
    void *task = nullptr;
    coroutine::Context ctx;
    Coroutine *origin = nullptr;
    CancelFunc *cancel_fn_ = nullptr;

    Coroutine(const CoroutineFunc &fn, void *private_data);
    long run();
    void check_end();
    void close();
};
//-------------------------------------------------------------------------------
namespace coroutine {
/**
 * Support for timeouts and cancellations requires the caller to store the memory pointers of
 * the input and output parameter objects in the `data` pointer of the `AsyncEvent` object.
 * This field is a `shared_ptr`, which increments the reference count when dispatched to the AIO thread,
 * collectively managing the `data` pointer.
 * When the async task is completed, the caller receives the results or cancels or timeouts,
 * the reference count will reach zero, and the memory will be released.
 */
bool async(async::Handler handler, AsyncEvent &event, double timeout = -1);
/**
 * This function should be used for asynchronous operations that do not support cancellation and timeouts.
 * For example, in write/read operations,
 * asynchronous tasks cannot transfer the memory ownership of wbuf/rbuf to the AIO thread.
 * In the event of a timeout or cancellation, the memory of wbuf/rbuf will be released by the caller,
 * which may lead the AIO thread to read from an erroneous memory pointer and consequently crash.
 */
bool async(const std::function<void()> &fn);
bool run(const CoroutineFunc &fn, void *arg = nullptr);
bool wait_for(const std::function<bool()> &fn);
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
