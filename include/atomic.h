#ifndef SW_ATOMIC_H_
#define SW_ATOMIC_H_

#if defined(__x86_64__)
#define SW_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)
typedef volatile int64_t atomic_int_t;
typedef volatile uint64_t atomic_uint_t;
#else
#define SW_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)
typedef volatile int32_t atomic_int_t;
typedef volatile uint32_t atomic_uint_t;
#endif

typedef volatile atomic_uint_t  atomic_t;

#define sw_atomic_cmp_set(lock, old, set) __sync_bool_compare_and_swap(lock, old, set)
#define sw_atomic_fetch_add(value, add)   __sync_fetch_and_add(value, add)
#define sw_atomic_fetch_sub(value, sub)   __sync_fetch_and_sub(value, sub)
#define sw_atomic_memory_barrier()        __sync_synchronize()
#define sw_atomic_cpu_pause()             __asm__ ("pause")

#endif
