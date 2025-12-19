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
  +----------------------------------------------------------------------+
*/

#include "swoole_coroutine.h"
#include "swoole_coroutine_api.h"

namespace swoole {

SW_THREAD_LOCAL Coroutine *Coroutine::current = nullptr;
SW_THREAD_LOCAL long Coroutine::last_cid = 0;
SW_THREAD_LOCAL long Coroutine::socket_bound_cid = 0;
SW_THREAD_LOCAL std::unordered_map<long, Coroutine *> Coroutine::coroutines;
SW_THREAD_LOCAL uint64_t Coroutine::peak_num = 0;
SW_THREAD_LOCAL bool Coroutine::activated = false;

SW_THREAD_LOCAL size_t Coroutine::stack_size = SW_DEFAULT_C_STACK_SIZE;
SW_THREAD_LOCAL Coroutine::SwapCallback Coroutine::on_yield = nullptr;
SW_THREAD_LOCAL Coroutine::SwapCallback Coroutine::on_resume = nullptr;
SW_THREAD_LOCAL Coroutine::SwapCallback Coroutine::on_close = nullptr;
SW_THREAD_LOCAL Coroutine::BailoutCallback Coroutine::on_bailout = nullptr;

#ifdef SW_USE_THREAD_CONTEXT
namespace coroutine {
void thread_context_init();
void thread_context_clean();
}  // namespace coroutine
#endif

void Coroutine::activate() {
#ifdef SW_USE_THREAD_CONTEXT
    coroutine::thread_context_init();
#endif
    activated = true;
    on_bailout = nullptr;
}

void Coroutine::deactivate() {
#ifdef SW_USE_THREAD_CONTEXT
    coroutine::thread_context_clean();
#endif
    activated = false;
    on_bailout = []() {
        // The coroutine scheduler has been destroyed,
        // Can not resume any coroutine
        // Expect that never here
        swoole_error("have been bailout, can not resume any coroutine");
    };
}

#ifdef SW_CORO_TIME
void Coroutine::calc_execute_usec(Coroutine *yield_coroutine, Coroutine *resume_coroutine) {
    long current_usec = time<seconds_type>(true);
    if (yield_coroutine) {
        yield_coroutine->execute_usec += current_usec - yield_coroutine->switch_usec;
    }

    if (resume_coroutine) {
        resume_coroutine->switch_usec = current_usec;
    }
}
#endif

Coroutine::Coroutine(const CoroutineFunc &fn, void *private_data) : ctx(stack_size, fn, private_data) {
    cid = ++last_cid;
    coroutines[cid] = this;
    if (sw_unlikely(count() > peak_num)) {
        peak_num = count();
    }
    if (!activated) {
        activate();
    }
}

void Coroutine::check_end() {
    if (ctx.is_end()) {
        close();
    } else if (sw_unlikely(on_bailout)) {
        SW_ASSERT(current == nullptr);
        on_bailout();
    }
}

long Coroutine::run() {
    const long _cid = cid;
    origin = current;
    current = this;
    CALC_EXECUTE_USEC(origin, nullptr);
    state = STATE_RUNNING;
    ctx.swap_in();
    check_end();
    return _cid;
}

void Coroutine::yield() {
    SW_ASSERT(current == this || on_bailout != nullptr);
    state = STATE_WAITING;
    resume_code_ = RC_OK;
    if (sw_likely(on_yield && task)) {
        on_yield(task);
    }
    current = origin;

    CALC_EXECUTE_USEC(this, current);
    ctx.swap_out();
}

void Coroutine::yield(CancelFunc *cancel_fn) {
    set_cancel_fn(cancel_fn);
    yield();
    set_cancel_fn(nullptr);
}

bool Coroutine::yield_ex(double timeout) {
    TimerNode *timer = nullptr;
    TimerCallback timer_callback = [this](Timer *timer, TimerNode *tnode) {
        resume_code_ = RC_TIMEDOUT;
        resume();
    };

    if (timeout > 0) {
        timer = swoole_timer_add(timeout, false, timer_callback, nullptr);
    }

    CancelFunc cancel_fn = [](Coroutine *co) {
        co->resume();
        return true;
    };

    yield(&cancel_fn);

    if (is_timedout()) {
        swoole_set_last_error(SW_ERROR_CO_TIMEDOUT);
        return false;
    }
    if (timer) {
        swoole_timer_del(timer);
    }
    if (is_canceled()) {
        swoole_set_last_error(SW_ERROR_CO_CANCELED);
        return false;
    }
    return true;
}

void Coroutine::resume() {
    SW_ASSERT(current != this);
    if (sw_unlikely(on_bailout)) {
        return;
    }
    state = STATE_RUNNING;
    if (sw_likely(on_resume && task)) {
        on_resume(task);
    }
    origin = current;
    current = this;

    CALC_EXECUTE_USEC(origin, this);
    ctx.swap_in();
    check_end();
}

bool Coroutine::cancel() {
    if (!cancel_fn_) {
        swoole_set_last_error(SW_ERROR_CO_CANNOT_CANCEL);
        return false;
    }
    auto fn = *cancel_fn_;
    set_cancel_fn(nullptr);
    resume_code_ = RC_CANCELED;
    return fn(this);
}

void Coroutine::close() {
    SW_ASSERT(current == this);
    state = STATE_END;
    if (on_close && task) {
        on_close(task);
    }
#if !defined(SW_USE_THREAD_CONTEXT) && defined(SW_CONTEXT_DETECT_STACK_USAGE)
    swoole_trace_log(
        SW_TRACE_CONTEXT, "coroutine#%ld stack memory use less than %ld bytes", get_cid(), ctx.get_stack_usage());
#endif
    current = origin;
    coroutines.erase(cid);
    delete this;
}

void Coroutine::print_list() {
    for (auto &coroutine : coroutines) {
        const char *state;
        switch (coroutine.second->state) {
        case STATE_INIT:
            state = "[INIT]";
            break;
        case STATE_WAITING:
            state = "[WAITING]";
            break;
        case STATE_RUNNING:
            state = "[RUNNING]";
            break;
        case STATE_END:
            state = "[END]";
            break;
        default:
            abort();
            return;
        }
        sw_printf("Coroutine\t%ld\t%s\n", coroutine.first, state);
    }
}

void Coroutine::print_socket_bound_error(int sock_fd, const char *event_str, long bound_cid) {
    socket_bound_cid = bound_cid;
    swoole_fatal_error(SW_ERROR_CO_HAS_BEEN_BOUND,
                       "Socket#%d has already been bound to another coroutine#%ld, "
                       "%s of the same socket in coroutine#%ld at the same time is not allowed",
                       sock_fd,
                       socket_bound_cid,
                       event_str,
                       get_current_cid());
}

void Coroutine::set_on_yield(const SwapCallback func) {
    on_yield = func;
}

void Coroutine::set_on_resume(const SwapCallback func) {
    on_resume = func;
}

void Coroutine::set_on_close(const SwapCallback func) {
    on_close = func;
}

void Coroutine::bailout(const BailoutCallback &func) {
    Coroutine *co = current;
    if (!co) {
        // marks that it can no longer resume any coroutine
        static BailoutCallback fn = []() {
            // expect that never here
            swoole_error("have been bailout, can not resume any coroutine");
        };
        on_bailout = fn;
        return;
    }
    if (!func) {
        swoole_error("bailout without callback function");
    }
    on_bailout = func;
    // find the coroutine which is closest to the main
    while (co->origin) {
        co = co->origin;
    }
    // it will jump to main context directly (it also breaks contexts)
    co->yield();
    // expect that never here
    exit(SW_CORO_BAILOUT_EXIT_CODE);
}

namespace coroutine {
bool run(const CoroutineFunc &fn, void *arg) {
    if (swoole_event_init(SW_EVENTLOOP_WAIT_EXIT) < 0) {
        return false;
    }
    Coroutine::activate();
    long cid = Coroutine::create(fn, arg);
    swoole_event_wait();
    Coroutine::deactivate();
    return cid > 0;
}
}  // namespace coroutine
}  // namespace swoole

uint8_t swoole_coroutine_is_in() {
    return !!swoole::Coroutine::get_current();
}

long swoole_coroutine_create(void (*routine)(void *), void *arg) {
    if (sw_likely(swoole_event_is_available())) {
        return swoole::Coroutine::create(routine, arg);
    } else {
        if (swoole_event_init(SW_EVENTLOOP_WAIT_EXIT) < 0) {
            return -1;
        }
        swoole::Coroutine::activate();
        long cid = swoole::Coroutine::create(routine, arg);
        swoole_event_wait();
        swoole::Coroutine::deactivate();
        return cid;
    }
}

long swoole_coroutine_get_id() {
    return swoole::Coroutine::get_current_cid();
}

swoole::Coroutine *swoole_coroutine_get(long cid) {
    auto i = swoole::Coroutine::coroutines.find(cid);
    if (i == swoole::Coroutine::coroutines.end()) {
        return nullptr;
    } else {
        return i->second;
    }
}

size_t swoole_coroutine_count() {
    return swoole::Coroutine::coroutines.size();
}

/**
 * for gdb
 */
static std::unordered_map<long, swoole::Coroutine *>::iterator gdb_iterator_;

void swoole_coroutine_iterator_reset() {
    gdb_iterator_ = swoole::Coroutine::coroutines.begin();
}

swoole::Coroutine *swoole_coroutine_iterator_each() {
    if (gdb_iterator_ == swoole::Coroutine::coroutines.end()) {
        return nullptr;
    }
    swoole::Coroutine *co = gdb_iterator_->second;
    ++gdb_iterator_;
    return co;
}
