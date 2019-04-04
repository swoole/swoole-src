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

#if USE_BOOST_CONTEXT

using namespace swoole;

Context::Context(size_t stack_size, coroutine_func_t fn, void* private_data) :
        fn_(fn), stack_size_(stack_size), private_data_(private_data)
{
    BOOST_ASSERT(boost::context::stack_traits::minimum_size() <= stack_size_);
    BOOST_ASSERT(
            boost::context::stack_traits::is_unbounded()
                    || (boost::context::stack_traits::maximum_size() >= stack_size_));

    protect_page_ = 0;
    end = false;
    swap_ctx_ = NULL;

    stack_ = (char*) sw_malloc(stack_size_);
    swTraceLog(SW_TRACE_COROUTINE, "alloc stack: size=%u, ptr=%p", stack_size_, stack_);

    void* sp = (void*) ((char*) stack_ + stack_size_);
#ifdef USE_VALGRIND
    valgrind_stack_id = VALGRIND_STACK_REGISTER(sp, stack_);
#endif
    ctx_ = boost::context::make_fcontext(sp, stack_size_, (void (*)(intptr_t))&context_func);

    uint32_t protect_page = get_protect_stack_page();
    if (protect_page)
    {
        if (protect_stack(stack_, stack_size_, protect_page))
        {
            protect_page_ = protect_page;
        }
    }
}

Context::~Context()
{
    if (stack_)
    {
        swTraceLog(SW_TRACE_COROUTINE, "free stack: ptr=%p", stack_);
        if (protect_page_)
        {
            unprotect_stack(stack_, protect_page_);
        }
#if defined(USE_VALGRIND)
        VALGRIND_STACK_DEREGISTER(valgrind_stack_id);
#endif
        sw_free(stack_);
        stack_ = NULL;
    }
}

bool Context::SwapIn()
{
    boost::context::jump_fcontext(&swap_ctx_, ctx_, (intptr_t) this, true);
    return true;
}

bool Context::SwapOut()
{
    boost::context::jump_fcontext(&ctx_, swap_ctx_, (intptr_t) this, true);
    return true;
}

void Context::context_func(void *arg)
{
    Context* _this = (Context*) arg;
    _this->fn_(_this->private_data_);
    _this->end = true;
    _this->SwapOut();
}

#endif
