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

#include "swoole_coroutine_context.h"

#ifdef SW_CONTEXT_PROTECT_STACK_PAGE
#include <sys/mman.h>
#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif

#ifndef SW_USE_THREAD_CONTEXT

#define MAGIC_STRING "swoole_coroutine#5652a7fb2b38be"
#define START_OFFSET (64 * 1024)

namespace swoole {
namespace coroutine {

Context::Context(size_t stack_size, const CoroutineFunc &fn, void *private_data)
    : fn_(fn), stack_size_(stack_size), private_data_(private_data) {
    end_ = false;

#ifdef SW_CONTEXT_PROTECT_STACK_PAGE
    int mapflags = MAP_PRIVATE | MAP_ANONYMOUS;
#ifdef __OpenBSD__
    // no-op for Linux and NetBSD, not to enable on FreeBSD as the semantic differs.
    // However necessary on OpenBSD.
    mapflags |= MAP_STACK;
#endif
    stack_ = (char *) ::mmap(0, stack_size_, PROT_READ | PROT_WRITE, mapflags, -1, 0);
#else
    stack_ = (char *) sw_malloc(stack_size_);
#endif
    if (!stack_) {
        swoole_fatal_error(SW_ERROR_MALLOC_FAIL, "failed to malloc stack memory.");
        exit(254);
    }
    swoole_trace_log(SW_TRACE_COROUTINE, "alloc stack: size=%u, ptr=%p", stack_size_, stack_);

    void *sp = (void *) ((char *) stack_ + stack_size_);
#ifdef USE_VALGRIND
    valgrind_stack_id = VALGRIND_STACK_REGISTER(sp, stack_);
#endif

#if USE_UCONTEXT
    if (-1 == getcontext(&ctx_)) {
        swoole_throw_error(SW_ERROR_CO_GETCONTEXT_FAILED);
        sw_free(stack_);
        return;
    }
    ctx_.uc_stack.ss_sp = stack_;
    ctx_.uc_stack.ss_size = stack_size;
    ctx_.uc_link = nullptr;
    makecontext(&ctx_, (void (*)(void)) & context_func, 1, this);
#else
    ctx_ = swoole_make_fcontext(sp, stack_size_, (void (*)(intptr_t)) & context_func);
    swap_ctx_ = nullptr;
#endif

#ifdef SW_CONTEXT_DETECT_STACK_USAGE
    size_t offset = START_OFFSET;
    while (offset <= stack_size) {
        memcpy((char *) sp - offset + (sizeof(MAGIC_STRING) - 1), SW_STRL(MAGIC_STRING));
        offset *= 2;
    }
#endif

#ifdef SW_CONTEXT_PROTECT_STACK_PAGE
    mprotect(stack_, SwooleG.pagesize, PROT_NONE);
#endif
}

Context::~Context() {
    if (stack_) {
        swoole_trace_log(SW_TRACE_COROUTINE, "free stack: ptr=%p", stack_);
#ifdef USE_VALGRIND
        VALGRIND_STACK_DEREGISTER(valgrind_stack_id);
#endif

#ifdef SW_CONTEXT_PROTECT_STACK_PAGE
        ::munmap(stack_, stack_size_);
#else
        sw_free(stack_);
#endif
        stack_ = nullptr;
    }
}

#ifdef SW_CONTEXT_DETECT_STACK_USAGE
ssize_t Context::get_stack_usage() {
    size_t offset = START_OFFSET;
    size_t retval = START_OFFSET;

    void *sp = (void *) ((char *) stack_ + stack_size_);

    while (offset < stack_size_) {
        if (memcmp((char *) sp - offset + (sizeof(MAGIC_STRING) - 1), SW_STRL(MAGIC_STRING)) != 0) {
            retval = offset * 2;
        }
        offset *= 2;
    }

    return retval;
}
#endif

bool Context::swap_in() {
#if USE_UCONTEXT
    return 0 == swapcontext(&swap_ctx_, &ctx_);
#else
    swoole_jump_fcontext(&swap_ctx_, ctx_, (intptr_t) this, true);
    return true;
#endif
}

bool Context::swap_out() {
#if USE_UCONTEXT
    return 0 == swapcontext(&ctx_, &swap_ctx_);
#else
    swoole_jump_fcontext(&ctx_, swap_ctx_, (intptr_t) this, true);
    return true;
#endif
}

void Context::context_func(void *arg) {
    Context *_this = (Context *) arg;
    _this->fn_(_this->private_data_);
    _this->end_ = true;
    _this->swap_out();
}
}  // namespace coroutine
}  // namespace swoole
#endif
