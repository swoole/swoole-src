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

intptr_t swoole_jump_fcontext(fcontext_t *ofc, fcontext_t nfc, intptr_t vp, bool preserve_fpu = false);
SW_INDIRECT_RETURN fcontext_t swoole_make_fcontext(void *sp, size_t size, void (*fn)(intptr_t));

SW_EXTERN_C_END

#endif
#endif
