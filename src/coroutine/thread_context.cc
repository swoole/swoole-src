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

#include "swoole_api.h"
#include "swoole_async.h"
#include "swoole_coroutine_context.h"

#ifdef SW_USE_THREAD_CONTEXT

namespace swoole {
namespace coroutine {

static std::mutex g_lock;
static Reactor *g_reactor = nullptr;
static Timer *g_timer = nullptr;
static String *g_buffer = nullptr;
static AsyncThreads *g_async_threads = nullptr;
static std::mutex *current_lock = nullptr;

static void empty_timer(Timer *timer, TimerNode *tnode) {
    // do nothing
}

Context::Context(size_t stack_size, const coroutine_func_t &fn, void *private_data)
    : fn_(fn), private_data_(private_data) {
    if (sw_unlikely(current_lock == nullptr)) {
        current_lock = &g_lock;
        if (SwooleTG.timer == nullptr) {
            swoole_timer_add(1, false, empty_timer, nullptr);
        }
//        if (SwooleTG.async_threads == nullptr) {
//            SwooleTG.async_threads = new AsyncThreads();
//        }
        g_reactor = SwooleTG.reactor;
        g_buffer = SwooleTG.buffer_stack;
        g_timer = SwooleTG.timer;
        g_async_threads = SwooleTG.async_threads;
        g_lock.lock();
    }
    end_ = false;
    lock_.lock();
    swap_lock_ = nullptr;
    thread_ = std::thread(Context::context_func, this);
}

Context::~Context() {
    thread_.join();
}

bool Context::swap_in() {
    swap_lock_ = current_lock;
    current_lock = &lock_;
    lock_.unlock();
    swap_lock_->lock();
    return true;
}

bool Context::swap_out() {
    current_lock = swap_lock_;
    swap_lock_->unlock();
    lock_.lock();
    return true;
}

void Context::context_func(void *arg) {
    Context *_this = (Context *) arg;
    SwooleTG.reactor = g_reactor;
    SwooleTG.timer = g_timer;
    SwooleTG.buffer_stack = g_buffer;
    SwooleTG.async_threads = g_async_threads;
    _this->lock_.lock();
    _this->fn_(_this->private_data_);
    _this->end_ = true;
    _this->swap_out();
}
}  // namespace coroutine
}  // namespace swoole
#endif
