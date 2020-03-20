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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#ifndef SW_ATOMIC_H_
#define SW_ATOMIC_H_

#ifdef _WIN32
typedef int32_t                     sw_atomic_int32_t;
typedef uint32_t                    sw_atomic_uint32_t;
typedef int64_t                     sw_atomic_int64_t;
typedef uint64_t                    sw_atomic_uint64_t;
typedef sw_atomic_uint32_t          sw_atomic_t;
typedef sw_atomic_uint64_t          sw_atomic_long_t;

static inline sw_atomic_t sw_atomic_cmp_set(sw_atomic_t *lock, sw_atomic_t old, sw_atomic_t set)
{
    if (*lock == old) {
        *lock = set;
        return 1;
    }

    return 0;
}

static inline sw_atomic_t sw_atomic_fetch_add(sw_atomic_t *value, sw_atomic_t add)
{
    sw_atomic_t  old;

    old = *value;
    *value += add;

    return old;
}

#define sw_memory_barrier()
#define sw_atomic_cpu_pause()

#else
typedef volatile int32_t                  sw_atomic_int32_t;
typedef volatile uint32_t                 sw_atomic_uint32_t;

#ifdef __x86_64__
typedef volatile int64_t                  sw_atomic_int64_t;
typedef volatile uint64_t                 sw_atomic_uint64_t;
#endif

#ifdef __x86_64__
typedef sw_atomic_int64_t                 sw_atomic_long_t;
typedef sw_atomic_uint64_t                sw_atomic_ulong_t;
#else
typedef sw_atomic_int32_t                 sw_atomic_long_t;
typedef sw_atomic_uint32_t                sw_atomic_ulong_t;
#endif

typedef sw_atomic_uint32_t                sw_atomic_t;

#define sw_atomic_cmp_set(lock, old, set) __sync_bool_compare_and_swap(lock, old, set)
#define sw_atomic_fetch_add(value, add)   __sync_fetch_and_add(value, add)
#define sw_atomic_fetch_sub(value, sub)   __sync_fetch_and_sub(value, sub)
#define sw_atomic_memory_barrier()        __sync_synchronize()
#define sw_atomic_add_fetch(value, add)   __sync_add_and_fetch(value, add)
#define sw_atomic_sub_fetch(value, sub)   __sync_sub_and_fetch(value, sub)

#ifdef __arm__
#define sw_atomic_cpu_pause()             __asm__ __volatile__ ("NOP");
#elif defined(__x86_64__)
#define sw_atomic_cpu_pause()             __asm__ __volatile__ ("pause")
#else
#define sw_atomic_cpu_pause()
#endif

#if 0
#define sw_spinlock_release(lock)         __sync_lock_release(lock)
#else
#define sw_spinlock_release(lock)         *(lock) = 0
#endif
#endif

#endif
