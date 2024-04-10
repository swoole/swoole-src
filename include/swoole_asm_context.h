/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2018 The Swoole Group                             |
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

#ifndef _SW_ASM_CONTEXT_H_
#define _SW_ASM_CONTEXT_H_

#ifdef SW_USE_ASM_CONTEXT

SW_EXTERN_C_BEGIN

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

typedef void *fcontext_t;

struct transfer_t {
    fcontext_t  fctx;
    void    *   data;
};

#ifdef __GNUC__
#define SW_GCC_VERSION (__GNUC__ * 1000 + __GNUC_MINOR__)
#else
#define SW_GCC_VERSION 0
#endif

#if defined(__GNUC__) && SW_GCC_VERSION >= 9000
#define SW_INDIRECT_RETURN __attribute__((__indirect_return__))
#else
#define SW_INDIRECT_RETURN
#endif

#undef SWOOLE_CONTEXT_CALLDECL
#if (defined(i386) || defined(__i386__) || defined(__i386) \
     || defined(__i486__) || defined(__i586__) || defined(__i686__) \
     || defined(__X86__) || defined(_X86_) || defined(__THW_INTEL__) \
     || defined(__I86__) || defined(__INTEL__) || defined(__IA32__) \
     || defined(_M_IX86) || defined(_I86_)) && defined(BOOST_WINDOWS)
# define SWOOLE_CONTEXT_CALLDECL __cdecl
#else
# define SWOOLE_CONTEXT_CALLDECL
#endif

transfer_t SWOOLE_CONTEXT_CALLDECL swoole_jump_fcontext(fcontext_t const to, void * vp);
fcontext_t SWOOLE_CONTEXT_CALLDECL swoole_make_fcontext(void *stack, size_t stack_size, void (* fn)(transfer_t));

SW_EXTERN_C_END

#endif
#endif
