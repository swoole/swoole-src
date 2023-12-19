/* Inspired from php-src's zend_call_stack.c */
/* Inspired from Chromium's stack_util.cc */

#include "swoole_call_stack.h"
#include <inttypes.h>
#ifdef ZEND_WIN32
# include <processthreadsapi.h>
# include <memoryapi.h>
#else /* ZEND_WIN32 */
# include <sys/resource.h>
# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif
# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif
#endif /* ZEND_WIN32 */
#if defined(__linux__) || defined(__FreeBSD__) || defined(__APPLE__) || defined(__OpenBSD__)
# include <pthread.h>
#endif
#ifdef __FreeBSD__
# include <pthread_np.h>
# include <sys/mman.h>
# include <sys/sysctl.h>
# include <sys/user.h>
#endif
#ifdef __OpenBSD__
typedef int boolean_t;
# include <tib.h>
# include <pthread_np.h>
# include <sys/sysctl.h>
# include <sys/user.h>
#endif
#ifdef __linux__
#include <sys/syscall.h>
#endif

namespace swoole {
    #ifdef __linux__
    static bool call_stack_is_main_thread(void) {
    # ifdef HAVE_GETTID
        return getpid() == gettid();
    # else
        return getpid() == syscall(SYS_gettid);
    # endif
    }

    #define HAVE_PTHREAD_GETATTR_NP 1
    #define HAVE_PTHREAD_ATTR_GETSTACK 1

    # if defined(HAVE_PTHREAD_GETATTR_NP) && defined(HAVE_PTHREAD_ATTR_GETSTACK)
    static bool call_stack_get_linux_pthread(call_stack *stack)
    {
        pthread_attr_t attr;
        int error;
        void *addr;
        size_t max_size;

        /* pthread_getattr_np() will return bogus values for the main thread with
        * musl or with some old glibc versions */
        SW_ASSERT(!call_stack_is_main_thread());

        error = pthread_getattr_np(pthread_self(), &attr);
        if (error) {
            return false;
        }

        error = pthread_attr_getstack(&attr, &addr, &max_size);
        if (error) {
            return false;
        }

    #  if defined(__GLIBC__) && (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 8))
        {
            size_t guard_size;
            /* In glibc prior to 2.8, addr and size include the guard pages */
            error = pthread_attr_getguardsize(&attr, &guard_size);
            if (error) {
                return false;
            }

            addr = (int8_t*)addr + guard_size;
            max_size -= guard_size;
        }
    #  endif /* glibc < 2.8 */

        stack->base = (int8_t*)addr + max_size;
        stack->max_size = max_size;

        return true;
    }
    # else /* defined(HAVE_PTHREAD_GETATTR_NP) && defined(HAVE_PTHREAD_ATTR_GETSTACK) */
    static bool call_stack_get_linux_pthread(call_stack *stack)
    {
        return false;
    }
    # endif /* defined(HAVE_PTHREAD_GETATTR_NP) && defined(HAVE_PTHREAD_ATTR_GETSTACK) */

    static bool call_stack_get_linux_proc_maps(call_stack *stack)
    {
        FILE *f;
        char buffer[4096];
        uintptr_t addr_on_stack = (uintptr_t)&buffer;
        uintptr_t start, end, prev_end = 0;
        size_t max_size;
        bool found = false;
        struct rlimit rlim;
        int error;

        /* This method is relevant only for the main thread */
        SW_ASSERT(call_stack_is_main_thread());

        /* Scan the process memory mappings to find the one containing the stack.
        *
        * The end of the stack mapping is the base of the stack. The start is
        * adjusted by the kernel as the stack grows. The maximum stack size is
        * determined by RLIMIT_STACK and the previous mapping.
        *
        *
        *                   ^ Higher addresses  ^
        *                   :                   :
        *                   :                   :
        *   Mapping end --> |-------------------| <-- Stack base (stack start)
        *                   |                   |   ^
        *                   | Stack Mapping     |   | Stack size
        *                   |                   |   v
        * Mapping start --> |-------------------| <-- Current stack end
        * (adjusted         :                   :
        *  downwards as the .                   .
        *  stack grows)     :                   :
        *                   |-------------------|
        *                   | Some Mapping      | The previous mapping may prevent
        *                   |-------------------| stack growth
        *                   :                   :
        *                   :                   :
        *                   v Lower addresses   v
        */

        f = fopen("/proc/self/maps", "r");
        if (!f) {
            return false;
        }

        while (fgets(buffer, sizeof(buffer), f) && sscanf(buffer, "%" SCNxPTR "-%" SCNxPTR, &start, &end) == 2) {
            if (start <= addr_on_stack && end >= addr_on_stack) {
                found = true;
                break;
            }
            prev_end = end;
        }

        fclose(f);

        if (!found) {
            return false;
        }

        error = getrlimit(RLIMIT_STACK, &rlim);
        if (error || rlim.rlim_cur == RLIM_INFINITY) {
            return false;
        }

        max_size = rlim.rlim_cur;

        /* Previous mapping may prevent the stack from growing */
        if (end - max_size < prev_end) {
            max_size = prev_end - end;
        }

        stack->base = (void*)end;
        stack->max_size = max_size;

        return true;
    }

    static bool call_stack_get_linux(call_stack *stack)
    {
        if (call_stack_is_main_thread()) {
            return call_stack_get_linux_proc_maps(stack);
        }

        return call_stack_get_linux_pthread(stack);
    }
    #else /* __linux__ */
    static bool call_stack_get_linux(call_stack *stack)
    {
        return false;
    }
    #endif /* __linux__ */

    #ifdef __FreeBSD__
    static bool call_stack_is_main_thread(void)
    {
        int is_main = pthread_main_np();
        return is_main == -1 || is_main == 1;
    }

    # if defined(HAVE_PTHREAD_ATTR_GET_NP) && defined(HAVE_PTHREAD_ATTR_GETSTACK)
    static bool call_stack_get_freebsd_pthread(call_stack *stack)
    {
        pthread_attr_t attr;
        int error;
        void *addr;
        size_t max_size;

        /* pthread will return bogus values for the main thread */
        SW_ASSERT(!call_stack_is_main_thread());

        pthread_attr_init(&attr);

        error = pthread_attr_get_np(pthread_self(), &attr);
        if (error) {
            goto fail;
        }

        error = pthread_attr_getstack(&attr, &addr, &max_size);
        if (error) {
            goto fail;
        }

        stack->base = (int8_t*)addr + max_size;
        stack->max_size = max_size;

        pthread_attr_destroy(&attr);
        return true;

    fail:
        pthread_attr_destroy(&attr);
        return false;
    }
    # else /* defined(HAVE_PTHREAD_ATTR_GET_NP) && defined(HAVE_PTHREAD_ATTR_GETSTACK) */
    static bool call_stack_get_freebsd_pthread(call_stack *stack)
    {
        return false;
    }
    # endif /* defined(HAVE_PTHREAD_ATTR_GET_NP) && defined(HAVE_PTHREAD_ATTR_GETSTACK) */

    static bool call_stack_get_freebsd_sysctl(call_stack *stack)
    {
        void *stack_base;
        int mib[2] = {CTL_KERN, KERN_USRSTACK};
        size_t len = sizeof(stack_base);
        struct rlimit rlim;

        /* This method is relevant only for the main thread */
        SW_ASSERT(call_stack_is_main_thread());

        if (sysctl(mib, sizeof(mib)/sizeof(*mib), &stack_base, &len, NULL, 0) != 0) {
            return false;
        }

        if (getrlimit(RLIMIT_STACK, &rlim) != 0) {
            return false;
        }

        if (rlim.rlim_cur == RLIM_INFINITY) {
            return false;
        }

        size_t guard_size = getpagesize();

        stack->base = stack_base;
        stack->max_size = rlim.rlim_cur - guard_size;

        return true;
    }

    static bool call_stack_get_freebsd(call_stack *stack)
    {
        if (call_stack_is_main_thread()) {
            return call_stack_get_freebsd_sysctl(stack);
        }

        return call_stack_get_freebsd_pthread(stack);
    }
    #else
    static bool call_stack_get_freebsd(call_stack *stack)
    {
        return false;
    }
    #endif /* __FreeBSD__ */

    #ifdef ZEND_WIN32
    static bool call_stack_get_win32(call_stack *stack)
    {
        ULONG_PTR low_limit, high_limit;
        ULONG size;
        MEMORY_BASIC_INFORMATION guard_region = {0}, uncommitted_region = {0};
        size_t result_size, page_size;

        /* The stack consists of three regions: committed, guard, and uncommitted.
        * Memory is committed when the guard region is accessed. If only one page
        * is left in the uncommitted region, a stack overflow error is raised
        * instead.
        *
        * The total useable stack size is the size of the committed and uncommitted
        * regions less one page.
        *
        * http://blogs.msdn.com/b/satyem/archive/2012/08/13/thread-s-stack-memory-management.aspx
        * https://learn.microsoft.com/en-us/windows/win32/procthread/thread-stack-size
        *
        *                ^  Higher addresses  ^
        *                :                    :
        *                :                    :
        * high_limit --> |--------------------|
        *            ^   |                    |
        *            |   | Committed region   |
        *            |   |                    |
        *            |   |------------------- | <-- guard_region.BaseAddress
        *   reserved |   |                    |     + guard_region.RegionSize
        *       size |   | Guard region       |
        *            |   |                    |
        *            |   |--------------------| <-- guard_region.BaseAddress,
        *            |   |                    |     uncommitted_region.BaseAddress
        *            |   | Uncommitted region |     + uncommitted_region.RegionSize
        *            v   |                    |
        * low_limit  --> |------------------- | <-- uncommitted_region.BaseAddress
        *                :                    :
        *                :                    :
        *                v  Lower addresses   v
        */

        GetCurrentThreadStackLimits(&low_limit, &high_limit);

        result_size = VirtualQuery((void*)low_limit,
                &uncommitted_region, sizeof(uncommitted_region));
        SW_ASSERT(result_size >= sizeof(uncommitted_region));

        result_size = VirtualQuery((int8_t*)uncommitted_region.BaseAddress + uncommitted_region.RegionSize,
                &guard_region, sizeof(guard_region));
        SW_ASSERT(result_size >= sizeof(uncommitted_region));

        stack->base = (void*)high_limit;
        stack->max_size = (uintptr_t)high_limit - (uintptr_t)low_limit;

        SW_ASSERT(stack->max_size > guard_region.RegionSize);
        stack->max_size -= guard_region.RegionSize;

        /* The uncommitted region does not shrink below 1 page */
        page_size = get_page_size();
        SW_ASSERT(stack->max_size > page_size);
        stack->max_size -= page_size;

        return true;
    }
    #else /* ZEND_WIN32 */
    static bool call_stack_get_win32(call_stack *stack)
    {
        return false;
    }
    #endif /* ZEND_WIN32 */

    #if defined(__APPLE__) && defined(HAVE_PTHREAD_GET_STACKADDR_NP)
    static bool call_stack_get_macos(call_stack *stack)
    {
        void *base = pthread_get_stackaddr_np(pthread_self());
        size_t max_size;

        if (pthread_main_np()) {
            /* pthread_get_stacksize_np() returns a too low value for the main
            * thread in OSX 10.9, 10.10:
            * https://mail.openjdk.org/pipermail/hotspot-dev/2013-October/011353.html
            * https://github.com/rust-lang/rust/issues/43347
            */

            /* Stack size is 8MiB by default for main threads
            * https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/Multithreading/CreatingThreads/CreatingThreads.html */
            max_size = 8 * 1024 * 1024;
        } else {
            max_size = pthread_get_stacksize_np(pthread_self());
        }

        stack->base = base;
        stack->max_size = max_size;

        return true;
    }
    #else /* defined(__APPLE__) && defined(HAVE_PTHREAD_GET_STACKADDR_NP) */
    static bool call_stack_get_macos(call_stack *stack)
    {
        return false;
    }
    #endif /* defined(__APPLE__) && defined(HAVE_PTHREAD_GET_STACKADDR_NP) */

    #if defined(__OpenBSD__)
    #if defined(HAVE_PTHREAD_STACKSEG_NP)
    static bool call_stack_get_openbsd_pthread(call_stack *stack)
    {
        stack_t ss;

        if (pthread_stackseg_np(pthread_self(), &ss) != 0) {
            return false;
        }

        stack->base = (char *)ss.ss_sp - ss.ss_size;
        stack->max_size = ss.ss_size - sysconf(_SC_PAGE_SIZE);

        return true;
    }
    #else
    static bool call_stack_get_openbsd_pthread(call_stack *stack)
    {
        return false;
    }
    #endif /* defined(HAVE_PTHREAD_STACKSEG_NP) */

    static bool call_stack_get_openbsd_vm(call_stack *stack)
    {
        struct _ps_strings ps;
        struct rlimit rlim;
        int mib[2] = {CTL_VM, VM_PSSTRINGS };
        size_t len = sizeof(ps), pagesize;

        if (sysctl(mib, 2, &ps, &len, NULL, 0) != 0) {
            return false;
        }

        if (getrlimit(RLIMIT_STACK, &rlim) != 0) {
            return false;
        }

        if (rlim.rlim_cur == RLIM_INFINITY) {
            return false;
        }

        pagesize = sysconf(_SC_PAGE_SIZE);

        stack->base = (void *)((uintptr_t)ps.val + (pagesize - 1) & ~(pagesize - 1));
        stack->max_size = rlim.rlim_cur - pagesize;

        return true;
    }

    static bool call_stack_get_openbsd(call_stack *stack)
    {
        // TIB_THREAD_INITIAL_STACK is private and here we avoid using pthread's api (ie pthread_main_np)
        if (!TIB_GET()->tib_thread || (TIB_GET()->tib_thread_flags & 0x002) != 0) {
            return call_stack_get_openbsd_vm(stack);
        }

        return call_stack_get_openbsd_pthread(stack);
    }

    #else
    static bool call_stack_get_openbsd(call_stack *stack)
    {
        return false;
    }
    #endif /* defined(__OpenBSD__) */

    /** Get the stack information for the calling thread */
    bool call_stack_get(call_stack *stack)
    {
        if (call_stack_get_linux(stack)) {
            return true;
        }

        if (call_stack_get_freebsd(stack)) {
            return true;
        }

        if (call_stack_get_win32(stack)) {
            return true;
        }

        if (call_stack_get_macos(stack)) {
            return true;
        }

        if (call_stack_get_openbsd(stack)) {
            return true;
        }

        return false;
    }
}
