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

#include "swoole.h"
#include "context.h"

#if USE_UCONTEXT

using namespace swoole;

Context::Context(size_t stack_size, coroutine_func_t fn, void* private_data) :
        fn_(fn), stack_size_(stack_size), private_data_(private_data)
{
    if (-1 == getcontext(&ctx_))
    {
        swoole_throw_error(SW_ERROR_CO_GETCONTEXT_FAILED);
        return;
    }

#ifdef SW_CONTEXT_PROTECT_STACK_PAGE
    protect_page_ = 0;
#endif
    end_ = false;

    stack_ = (char*) sw_malloc(stack_size);
    swTraceLog(SW_TRACE_COROUTINE, "alloc stack: size=%lu, ptr=%p", stack_size, stack_);

    ctx_.uc_stack.ss_sp = stack_;
    ctx_.uc_stack.ss_size = stack_size;
    ctx_.uc_link = NULL;

#if defined(USE_VALGRIND)
    valgrind_stack_id = VALGRIND_STACK_REGISTER(static_cast<char *>(stack_) + stack_size, stack_);
#endif

    makecontext(&ctx_, (void (*)(void))&context_func, 1, this);

#ifdef SW_CONTEXT_PROTECT_STACK_PAGE
    uint32_t protect_page = get_protect_stack_page();
    if (protect_page)
    {
        if (protect_stack(stack_, stack_size, protect_page))
        {
            protect_page_ = protect_page;
        }
    }
#endif
}

Context::~Context()
{
    if (stack_)
    {
        swTraceLog(SW_TRACE_COROUTINE, "free stack: ptr=%p", stack_);
#ifdef SW_CONTEXT_PROTECT_STACK_PAGE
        if (protect_page_)
        {
            unprotect_stack(stack_, protect_page_);
        }
#endif

#if defined(USE_VALGRIND)
        VALGRIND_STACK_DEREGISTER(valgrind_stack_id);
#endif
        sw_free(stack_);
        stack_ = NULL;
    }
}

bool Context::swap_in()
{
    return 0 == swapcontext(&swap_ctx_, &ctx_);
}

bool Context::swap_out()
{
    return 0 == swapcontext(&ctx_, &swap_ctx_);
}

void Context::context_func(void *arg)
{
    Context *_this = (Context *) arg;
    _this->fn_(_this->private_data_);
    _this->end_ = true;
    _this->swap_out();
}

#endif
