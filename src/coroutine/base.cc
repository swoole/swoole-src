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
#include "swoole_coroutine_c_api.h"

namespace swoole {

Coroutine *Coroutine::current = nullptr;
long Coroutine::last_cid = 0;
std::unordered_map<long, Coroutine *> Coroutine::coroutines;
uint64_t Coroutine::peak_num = 0;
bool Coroutine::activated = false;

size_t Coroutine::stack_size = SW_DEFAULT_C_STACK_SIZE;
Coroutine::SwapCallback Coroutine::on_yield = nullptr;
Coroutine::SwapCallback Coroutine::on_resume = nullptr;
Coroutine::SwapCallback Coroutine::on_close = nullptr;
Coroutine::BailoutCallback Coroutine::on_bailout = nullptr;

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
}

void Coroutine::deactivate() {
#ifdef SW_USE_THREAD_CONTEXT
    coroutine::thread_context_clean();
#endif
    activated = false;
}

void Coroutine::yield() {
    SW_ASSERT(current == this || on_bailout != nullptr);
    state = STATE_WAITING;
    resume_code_ = RC_OK;
    if (sw_likely(on_yield && task)) {
        on_yield(task);
    }
    current = origin;
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
    for (auto i = coroutines.begin(); i != coroutines.end(); i++) {
        const char *state;
        switch (i->second->state) {
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
        printf("Coroutine\t%ld\t%s\n", i->first, state);
    }
}

void Coroutine::set_on_yield(SwapCallback func) {
    on_yield = func;
}

void Coroutine::set_on_resume(SwapCallback func) {
    on_resume = func;
}

void Coroutine::set_on_close(SwapCallback func) {
    on_close = func;
}

void Coroutine::bailout(BailoutCallback func) {
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

long swoole_coroutine_get_current_id() {
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
static std::unordered_map<long, swoole::Coroutine *>::iterator _gdb_iterator;

void swoole_coroutine_iterator_reset() {
    _gdb_iterator = swoole::Coroutine::coroutines.begin();
}

swoole::Coroutine *swoole_coroutine_iterator_each() {
    if (_gdb_iterator == swoole::Coroutine::coroutines.end()) {
        return nullptr;
    } else {
        swoole::Coroutine *co = _gdb_iterator->second;
        _gdb_iterator++;
        return co;
    }
}
