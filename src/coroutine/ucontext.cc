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

    protect_page_ = 0;
    end = false;

    stack_ = (char*) sw_malloc(stack_size);
    swDebug("alloc stack: size=%lu, ptr=%p", stack_size, stack_);

    ctx_.uc_stack.ss_sp = stack_;
    ctx_.uc_stack.ss_size = stack_size;
    ctx_.uc_link = NULL;

#if defined(USE_VALGRIND)
    valgrind_stack_id = VALGRIND_STACK_REGISTER(static_cast<char *>(stack_) + stack_size, stack_);
#endif

    makecontext(&ctx_, (void (*)(void))&context_func, 1, this);

    uint32_t protect_page = get_protect_stack_page();
    if (protect_page)
    {
        if (protect_stack(stack_, stack_size, protect_page))
        {
            protect_page_ = protect_page;
        }
    }
}

Context::~Context()
{
    if (stack_)
    {
        swDebug("free stack: ptr=%p", stack_);
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
    return 0 == swapcontext(&swap_ctx_, &ctx_);
}

bool Context::SwapOut()
{
    return 0 == swapcontext(&ctx_, &swap_ctx_);
}

void Context::context_func(void *arg)
{
    Context *_this = (Context *) arg;
    _this->fn_(_this->private_data_);
    _this->end = true;
    _this->SwapOut();
}

#endif
