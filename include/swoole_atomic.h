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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

typedef volatile int32_t sw_atomic_int32_t;
typedef volatile uint32_t sw_atomic_uint32_t;
typedef volatile int64_t sw_atomic_int64_t;
typedef volatile uint64_t sw_atomic_uint64_t;

typedef sw_atomic_int64_t sw_atomic_long_t;
typedef sw_atomic_uint64_t sw_atomic_ulong_t;
typedef sw_atomic_uint32_t sw_atomic_t;

#ifdef _MSC_VER

#include <intrin.h>

// MSVC does not support GCC __sync_* builtins.
// Use _Interlocked* intrinsics instead.

// 32-bit atomic operations
#define sw_atomic_cmp_set(lock, old, set) \
    (_InterlockedCompareExchange(reinterpret_cast<volatile LONG *>(lock), \
                                  static_cast<LONG>(set), static_cast<LONG>(old)) == static_cast<LONG>(old))

#define sw_atomic_value_cmp_set(value, expected, set) \
    _InterlockedCompareExchange(reinterpret_cast<volatile LONG *>(value), \
                                 static_cast<LONG>(set), static_cast<LONG>(expected))

#define sw_atomic_fetch_add(value, add) \
    _InterlockedExchangeAdd(reinterpret_cast<volatile LONG *>(value), static_cast<LONG>(add))

#define sw_atomic_fetch_sub(value, sub) \
    _InterlockedExchangeAdd(reinterpret_cast<volatile LONG *>(value), -static_cast<LONG>(sub))

#define sw_atomic_memory_barrier() MemoryBarrier()

#define sw_atomic_add_fetch(value, add) \
    (_InterlockedExchangeAdd(reinterpret_cast<volatile LONG *>(value), static_cast<LONG>(add)) + static_cast<LONG>(add))

#define sw_atomic_sub_fetch(value, sub) \
    (_InterlockedExchangeAdd(reinterpret_cast<volatile LONG *>(value), -static_cast<LONG>(sub)) - static_cast<LONG>(sub))

// 64-bit atomic operations (for sw_atomic_int64_t / sw_atomic_long_t)
#define sw_atomic_cmp_set_64(lock, old, set) \
    (_InterlockedCompareExchange64(reinterpret_cast<volatile __int64 *>(lock), \
                                    static_cast<__int64>(set), static_cast<__int64>(old)) == static_cast<__int64>(old))

#define sw_atomic_fetch_add_64(value, add) \
    _InterlockedExchangeAdd64(reinterpret_cast<volatile __int64 *>(value), static_cast<__int64>(add))

#define sw_atomic_fetch_sub_64(value, sub) \
    _InterlockedExchangeAdd64(reinterpret_cast<volatile __int64 *>(value), -static_cast<__int64>(sub))

#define sw_atomic_add_fetch_64(value, add) \
    (_InterlockedExchangeAdd64(reinterpret_cast<volatile __int64 *>(value), static_cast<__int64>(add)) + static_cast<__int64>(add))

#define sw_atomic_sub_fetch_64(value, sub) \
    (_InterlockedExchangeAdd64(reinterpret_cast<volatile __int64 *>(value), -static_cast<__int64>(sub)) - static_cast<__int64>(sub))

#define sw_spinlock_release(lock) \
    _InterlockedExchange(reinterpret_cast<volatile LONG *>(lock), 0)

#define sw_atomic_cpu_pause() _mm_pause()

#else  // GCC/Clang

#define sw_atomic_cmp_set(lock, old, set) __sync_bool_compare_and_swap(lock, old, set)
#define sw_atomic_value_cmp_set(value, expected, set) __sync_val_compare_and_swap(value, expected, set)
#define sw_atomic_fetch_add(value, add) __sync_fetch_and_add(value, add)
#define sw_atomic_fetch_sub(value, sub) __sync_fetch_and_sub(value, sub)
#define sw_atomic_memory_barrier() __sync_synchronize()
#define sw_atomic_add_fetch(value, add) __sync_add_and_fetch(value, add)
#define sw_atomic_sub_fetch(value, sub) __sync_sub_and_fetch(value, sub)

#define sw_spinlock_release(lock) __sync_lock_release(lock)

#if defined(__x86_64__)
#define sw_atomic_cpu_pause() __asm__ __volatile__("pause")
#elif defined(__aarch64__)
#define sw_atomic_cpu_pause() __asm__ __volatile__("yield")
#else
#define sw_atomic_cpu_pause()
#endif

#endif  // _MSC_VER

void sw_spinlock(sw_atomic_t *lock);
int sw_atomic_futex_wait(sw_atomic_t *atomic, double timeout);
int sw_atomic_futex_wakeup(sw_atomic_t *atomic, int n);
