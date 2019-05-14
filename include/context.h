#pragma once

#ifdef SW_NO_USE_ASM_CONTEXT
#ifdef HAVE_BOOST_CONTEXT
#define USE_BOOST_CONTEXT 1
#include <boost/context/all.hpp>
#else
#define USE_UCONTEXT 1
#include <ucontext.h>
#endif
#else
#include "asm_context.h"
#endif

#if defined(HAVE_VALGRIND) && !defined(HAVE_KQUEUE)
#define USE_VALGRIND 1
#endif

#include "swoole.h"
#include "error.h"

#if __linux__
#include <sys/mman.h>
#endif

#ifdef USE_BOOST_CONTEXT
    typedef boost::context::fcontext_t coroutine_context_t;
#elif USE_UCONTEXT
    typedef ucontext_t coroutine_context_t;
#else
    typedef fcontext_t coroutine_context_t;
#endif
typedef void (*coroutine_func_t)(void*);

namespace swoole
{
#ifdef SW_CONTEXT_PROTECT_STACK_PAGE
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
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_CO_PROTECT_STACK_FAILED, "getpagesize() failed");
        return false;
    }
#ifdef PROT_NONE
    void *protect_page_addr = ((size_t) top & 0xfff) ? (void*) (((size_t) top & ~(size_t) 0xfff) + 0x1000) : top;
    if (-1 == mprotect(protect_page_addr, SwooleG.pagesize * page, PROT_NONE))
    {
        swSysWarn(
            "mprotect() failed: origin_addr:%p, align_addr:%p, page_size:%d, protect_page:%u",
            top, protect_page_addr, SwooleG.pagesize, page
        );
        return false;
    }
    else
    {
        swDebug("origin_addr:%p, align_addr:%p, page_size:%d, protect_page:%u", top, protect_page_addr, page, SwooleG.pagesize);
        return true;
    }
#endif
}
static bool unprotect_stack(void *top, uint32_t page)
{
    void *protect_page_addr = ((size_t) top & 0xfff) ? (void*) (((size_t) top & ~(size_t) 0xfff) + 0x1000) : top;
#ifdef PROT_READ
    if (-1 == mprotect(protect_page_addr, SwooleG.pagesize * page, PROT_READ | PROT_WRITE))
    {
        swSysWarn(
            "mprotect() failed: origin_addr:%p, align_addr:%p, page_size:%d, protect_page:%u",
            top, protect_page_addr, SwooleG.pagesize, page
        );
        return false;
    }
    else
    {
        swDebug("origin_addr:%p, align_addr:%p, page_size:%d, protect_page:%u", top, protect_page_addr, page, SwooleG.pagesize);
        return true;
    }
#endif
}
#endif

class Context
{
public:
    Context(size_t stack_size, coroutine_func_t fn, void* private_data);
    ~Context();
    bool swap_in();
    bool swap_out();
#if !defined(SW_NO_USE_ASM_CONTEXT) && defined(SW_LOG_TRACE_OPEN)
    ssize_t get_stack_usage();
#endif
    inline bool is_end()
    {
        return end_;
    }
    static void context_func(void* arg);

protected:
    coroutine_context_t ctx_;
    coroutine_context_t swap_ctx_;
    coroutine_func_t fn_;
    char* stack_;
    uint32_t stack_size_;
#ifdef SW_CONTEXT_PROTECT_STACK_PAGE
    uint32_t protect_page_;
#endif
#ifdef USE_VALGRIND
    uint32_t valgrind_stack_id;
#endif
    void *private_data_;
    bool end_;
};
//namespace end
}
