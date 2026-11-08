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
#ifndef _WIN32
#include <sys/mman.h>
#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif
#endif

#ifndef SW_USE_THREAD_CONTEXT

#define MAGIC_STRING "swoole_coroutine#5652a7fb2b38be"
#define START_OFFSET (64 * 1024)

namespace swoole {
namespace coroutine {

Context::Context(size_t stack_size, CoroutineFunc fn, void *private_data)
    : fn_(std::move(fn)), stack_(nullptr, StackDeleter{stack_size}), private_data_(private_data) {
    end_ = false;

#ifdef SW_CONTEXT_PROTECT_STACK_PAGE
    int mapflags = MAP_PRIVATE | MAP_ANONYMOUS;
#ifdef __OpenBSD__
    // no-op for Linux and NetBSD, not to enable on FreeBSD as the semantic differs.
    // However, necessary on OpenBSD.
    mapflags |= MAP_STACK;
#endif
    auto *stack = static_cast<char *>(::mmap(nullptr, stack_size, PROT_READ | PROT_WRITE, mapflags, -1, 0));
#else
    auto *stack = static_cast<char *>(sw_malloc(stack_size));
#endif
#ifdef SW_CONTEXT_PROTECT_STACK_PAGE
    if (stack == MAP_FAILED) {
#else
    if (!stack) {
#endif
        swoole_fatal_error(SW_ERROR_MALLOC_FAIL, "failed to malloc stack memory.");
        exit(254);
    }
    stack_.reset(stack);
    swoole_trace_log(SW_TRACE_COROUTINE, "alloc stack: size=%zu, ptr=%p", stack_size, stack);

    void *sp = stack + stack_size;
#ifdef USE_VALGRIND
    stack_.get_deleter().valgrind_stack_id = VALGRIND_STACK_REGISTER(sp, stack);
#endif

#ifdef USE_UCONTEXT
    if (-1 == getcontext(&ctx_)) {
        swoole_throw_error(SW_ERROR_CO_GETCONTEXT_FAILED);
    }
    ctx_.uc_stack.ss_sp = stack;
    ctx_.uc_stack.ss_size = stack_size;
    ctx_.uc_link = nullptr;
    makecontext(&ctx_, (void (*)(void)) &context_func, 1, this);
#else
    ctx_ = swoole_make_fcontext(sp, stack_size, (void (*)(transfer_t)) &context_func);
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
    mprotect(stack, SwooleG.pagesize, PROT_NONE);
#endif
}

void Context::StackDeleter::operator()(char *stack) const noexcept {
    swoole_trace_log(SW_TRACE_COROUTINE, "free stack: ptr=%p", stack);
#ifdef USE_VALGRIND
    VALGRIND_STACK_DEREGISTER(valgrind_stack_id);
#endif

#ifdef SW_CONTEXT_PROTECT_STACK_PAGE
    ::munmap(stack, size);
#else
    sw_free(stack);
#endif
}

Context::~Context() = default;

#ifdef SW_CONTEXT_DETECT_STACK_USAGE
ssize_t Context::get_stack_usage() {
    size_t offset = START_OFFSET;
    size_t retval = START_OFFSET;

    void *sp = stack_.get() + get_stack_size();

    while (offset < get_stack_size()) {
        if (memcmp((char *) sp - offset + (sizeof(MAGIC_STRING) - 1), SW_STRL(MAGIC_STRING)) != 0) {
            retval = offset * 2;
        }
        offset *= 2;
    }

    return retval;
}
#endif

bool Context::swap_in() {
#ifdef USE_UCONTEXT
    return 0 == swapcontext(&swap_ctx_, &ctx_);
#else
    coroutine_transfer_t transfer_data = swoole_jump_fcontext(ctx_, (void *) this);
    ctx_ = transfer_data.fctx;
    return true;
#endif
}

bool Context::swap_out() {
#ifdef USE_UCONTEXT
    return 0 == swapcontext(&ctx_, &swap_ctx_);
#else
    coroutine_transfer_t transfer_data = swoole_jump_fcontext(swap_ctx_, (void *) this);
    swap_ctx_ = transfer_data.fctx;
    return true;
#endif
}

void Context::context_func(coroutine_transfer_t arg) {
#if defined(USE_UCONTEXT) || defined(SW_USE_THREAD_CONTEXT)
    auto *_this = (Context *) arg;
#else
    auto *_this = (Context *) arg.data;
    _this->swap_ctx_ = arg.fctx;
#endif
    _this->fn_(_this->private_data_);
    _this->end_ = true;
    _this->swap_out();
}
}  // namespace coroutine
}  // namespace swoole
#endif
