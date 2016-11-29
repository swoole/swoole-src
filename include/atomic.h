#ifndef SW_ATOMIC_H_
#define SW_ATOMIC_H_

#if defined(__x86_64__)
#define SW_ATOMIC_64_LEN                     (sizeof("-9223372036854775808") - 1)
typedef volatile int64_t atomic_int64_t;
typedef volatile uint64_t atomic_uint64_t;
#endif

#define SW_ATOMIC_32_LEN                      (sizeof("-2147483648") - 1)
typedef volatile int32_t atomic_int32_t;
typedef volatile uint32_t atomic_uint32_t;
typedef atomic_uint32_t  sw_atomic_t;

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

#define sw_spinlock_release(lock)         __sync_lock_release(lock)

#endif
