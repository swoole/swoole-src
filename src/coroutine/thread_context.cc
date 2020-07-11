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
#include "context.h"

#ifdef SW_USE_THREAD_CONTEXT

using namespace swoole;
using namespace std;

static mutex global_lock;
static swReactor *g_reactor = nullptr;
static swTimer *g_timer = nullptr;
static mutex *current_lock = nullptr;

static void empty_timer(swTimer *timer, swTimer_node *tnode) {
    // do nothing
}

Context::Context(size_t stack_size, coroutine_func_t fn, void *private_data) : fn_(fn), private_data_(private_data) {
    if (sw_unlikely(current_lock == nullptr)) {
        current_lock = &global_lock;
        g_reactor = SwooleTG.reactor;
        if (SwooleTG.timer == nullptr) {
            swoole_timer_add(1, 0, empty_timer, nullptr);
        }
        g_timer = SwooleTG.timer;
        global_lock.lock();
    }
    end_ = false;
    lock_.lock();
    thread_ = thread(Context::context_func, this);
}

Context::~Context() {
    thread_.join();
}

bool Context::swap_in() {
    swap_lock_ = current_lock;
    current_lock = &lock_;
    lock_.unlock();
    swap_lock_->lock();
}

bool Context::swap_out() {
    current_lock = swap_lock_;
    swap_lock_->unlock();
    lock_.lock();
}

void Context::context_func(void *arg) {
    Context *_this = (Context *) arg;
    SwooleTG.reactor = g_reactor;
    SwooleTG.timer = g_timer;
    _this->lock_.lock();
    _this->fn_(_this->private_data_);
    _this->lock_.unlock();
    _this->swap_lock_->unlock();
    _this->end_ = true;
}

#endif
