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

#pragma once

#include "swoole.h"
#include "swoole_lock.h"

#include <thread>

#if defined(__linux__)
#include <sys/syscall.h> /* syscall(SYS_gettid) */
#elif defined(__FreeBSD__)
#include <pthread_np.h> /* pthread_getthreadid_np() */
#elif defined(__OpenBSD__)
#include <unistd.h> /* getthrid() */
#elif defined(_AIX)
#include <sys/thread.h> /* thread_self() */
#elif defined(__NetBSD__)
#include <lwp.h> /* _lwp_self() */
#elif defined(__CYGWIN__) || defined(WIN32)
#include <windows.h> /* GetCurrentThreadId() */
#endif

static long swoole_thread_get_native_id(void) {
#ifdef __APPLE__
    uint64_t native_id;
    (void) pthread_threadid_np(NULL, &native_id);
#elif defined(__linux__)
    pid_t native_id = syscall(SYS_gettid);
#elif defined(__FreeBSD__)
    int native_id = pthread_getthreadid_np();
#elif defined(__OpenBSD__)
    pid_t native_id = getthrid();
#elif defined(_AIX)
    tid_t native_id = thread_self();
#elif defined(__NetBSD__)
    lwpid_t native_id = _lwp_self();
#elif defined(__CYGWIN__) || defined(WIN32)
    DWORD native_id = GetCurrentThreadId();
#endif
    return native_id;
}

static bool swoole_thread_set_name(const char *name) {
#if defined(__APPLE__)
    return pthread_setname_np(name) == 0;
#else
    return pthread_setname_np(pthread_self(), name) == 0;
#endif
}
