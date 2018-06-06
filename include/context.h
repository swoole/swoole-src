#pragma once

#define USE_UCONTEXT 1
#define USE_BOOST_CONTEXT 0

#ifdef HAVE_VALGRIND
#define USE_VALGRIND 1
#endif

#include "swoole.h"
#include "coroutine.h"
#include "error.h"

#if __linux__
#include <sys/mman.h>
#endif

#ifdef USE_VALGRIND
#include <valgrind/valgrind.h>
#endif

namespace swoole
{
//namespace start
static uint32_t& get_protect_stack_page()
{
    static uint32_t protect_stack_page = 0;
    return protect_stack_page;
}

static bool protect_stack(void *top, size_t stack_size, uint32_t page)
{
    if (stack_size <= SwooleG.pagesize * (page + 1))
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_CO_PROTECT_STACK_FAILED, "getpagesize() failed.");
        return false;
    }

    void *protect_page_addr = ((size_t) top & 0xfff) ? (void*) (((size_t) top & ~(size_t) 0xfff) + 0x1000) : top;
    if (-1 == mprotect(protect_page_addr, SwooleG.pagesize * page, PROT_NONE))
    {
        swSysError("mprotect() failed: origin_addr:%p, align_addr:%p, page_size:%d, protect_page:%u.", top,
                protect_page_addr, SwooleG.pagesize, page);
        return false;
    }
    else
    {
        swDebug("origin_addr:%p, align_addr:%p, page_size:%d, protect_page:%u", top, protect_page_addr, page, SwooleG.pagesize);
        return true;
    }
}
static bool unprotect_stack(void *top, uint32_t page)
{
    void *protect_page_addr = ((size_t) top & 0xfff) ? (void*) (((size_t) top & ~(size_t) 0xfff) + 0x1000) : top;
    if (-1 == mprotect(protect_page_addr, SwooleG.pagesize * page, PROT_READ | PROT_WRITE))
    {
        swSysError("mprotect() failed: origin_addr:%p, align_addr:%p, page_size:%d, protect_page:%u.", top,
                protect_page_addr, SwooleG.pagesize, page);
        return false;
    }
    else
    {
        swDebug("origin_addr:%p, align_addr:%p, page_size:%d, protect_page:%u.", top, protect_page_addr, page, SwooleG.pagesize);
        return true;
    }
}
//namespace end
}

/**
 * boost.context
 */
#if USE_BOOST_CONTEXT
#include <boost/context/all.hpp>

static boost::context::fcontext_t tls_context;

namespace swoole
{
    class Context
    {
    public:
        Context(size_t stack_size, coroutine_func_t fn, void* private_data) :
        fn_(fn), stack_size_(stack_size), private_data_(private_data)
        {
            BOOST_ASSERT(boost::context::stack_traits::minimum_size() <= stack_size_);
            BOOST_ASSERT(
                    boost::context::stack_traits::is_unbounded()
                    || (boost::context::stack_traits::maximum_size() >= stack_size_));

            protect_page_ = 0;
            end = false;

            stack_ = (char*) sw_malloc(stack_size_);
            swDebug("alloc stack: size=%lu, ptr=%p.", stack_size_, stack_);

            void* sp = (void*) ((char*) stack_ + stack_size_);
#if defined(USE_VALGRIND)
            valgrind_stack_id = VALGRIND_STACK_REGISTER(sp, stack_);
#endif
            ctx_ = boost::context::make_fcontext(sp, stack_size_, &fcontext_func);

            uint32_t protect_page = get_protect_stack_page();
            if (protect_page)
            {
                if (protect_stack(stack_, stack_size_, protect_page))
                {
                    protect_page_ = protect_page;
                }
            }
        }
        ~Context()
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

        inline bool SwapIn()
        {
            boost::context::jump_fcontext(&tls_context, ctx_, (intptr_t) this, true);
            return true;
        }

        inline bool SwapOut()
        {
            boost::context::jump_fcontext(&ctx_, &tls_context, (intptr_t) this, true);
            return true;
        }

        static void fcontext_func(intptr_t arg)
        {
            Context* _this = (Context*) arg;
            _this->fn_(_this->private_data_);
            _this->end = true;
            _this->SwapOut();
        }

    public:
        bool end;

    private:
        boost::context::fcontext_t ctx_;
        coroutine_func_t fn_;
        char* stack_;
        uint32_t stack_size_;
        uint32_t protect_page_;
        uint32_t valgrind_stack_id;
        void *private_data_;
    };

} //namespace end

/**
 * ucontext
 */
#elif USE_UCONTEXT
#include <ucontext.h>

static __thread ucontext_t tls_context;

namespace swoole
{
class Context
{
public:
    Context(size_t stack_size, coroutine_func_t fn, void* private_data) :
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
        swWarn("alloc stack: size=%lu, ptr=%p", stack_size, stack_);

        ctx_.uc_stack.ss_sp = stack_;
        ctx_.uc_stack.ss_size = stack_size;
        ctx_.uc_link = NULL;

#if defined(USE_VALGRIND)
        valgrind_stack_id = VALGRIND_STACK_REGISTER(static_cast<char *>(stack_) + stack_size, stack_);
#endif

        makecontext(&ctx_, (void (*)(void))&ucontext_func, 1, this);

        uint32_t protect_page = get_protect_stack_page();
        if (protect_page)
        {
            if (protect_stack(stack_, stack_size, protect_page))
            {
                protect_page_ = protect_page;
            }
        }
    }
    ~Context()
    {
        if (stack_)
        {
            swWarn("free stack: ptr=%p", stack_);
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

    inline bool SwapIn()
    {
        return 0 == swapcontext(&tls_context, &ctx_);
    }

    inline bool SwapOut()
    {
        return 0 == swapcontext(&ctx_, &tls_context);
    }

    static void ucontext_func(Context *_this)
    {
        _this->fn_(_this->private_data_);
        _this->end = true;
        _this->SwapOut();
    }

public:
    bool end;

private:
    uint32_t valgrind_stack_id;
    ucontext_t ctx_;
    coroutine_func_t fn_;
    uint32_t stack_size_;
    char *stack_;
    void *private_data_;
    uint32_t protect_page_;
};

}
#else
# error "require ucontext or boost.context."
#endif
