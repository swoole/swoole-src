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

#include "swoole.h"

void sw_spinlock(sw_atomic_t *lock) {
    uint32_t i, n;
    while (true) {
        if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1)) {
            return;
        }
        if (SW_CPU_NUM > 1) {
            for (n = 1; n < SW_SPINLOCK_LOOP_N; n <<= 1) {
                for (i = 0; i < n; i++) {
                    sw_atomic_cpu_pause();
                }

                if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1)) {
                    return;
                }
            }
        }
        sw_yield();
    }
}

#ifdef HAVE_FUTEX
#include <linux/futex.h>
#include <sys/syscall.h>

int sw_atomic_futex_wait(sw_atomic_t *atomic, double timeout) {
    if (sw_atomic_cmp_set(atomic, 1, 0)) {
        return 0;
    }

    int ret;
    timespec _timeout;

    if (timeout > 0) {
        _timeout.tv_sec = static_cast<long>(timeout);
        _timeout.tv_nsec = (timeout - _timeout.tv_sec) * 1000 * 1000 * 1000;
        ret = syscall(SYS_futex, atomic, FUTEX_WAIT, 0, &_timeout, NULL, 0);
    } else {
        ret = syscall(SYS_futex, atomic, FUTEX_WAIT, 0, NULL, NULL, 0);
    }
    if (ret == 0 && sw_atomic_cmp_set(atomic, 1, 0)) {
        return 0;
    } else {
        return -1;
    }
}

int sw_atomic_futex_wakeup(sw_atomic_t *atomic, int n) {
    if (sw_atomic_cmp_set(atomic, 0, 1)) {
        return syscall(SYS_futex, atomic, FUTEX_WAKE, n, NULL, NULL, 0);
    } else {
        return 0;
    }
}
#else
int sw_atomic_futex_wait(sw_atomic_t *atomic, double timeout) {
    if (sw_atomic_cmp_set(atomic, (sw_atomic_t) 1, (sw_atomic_t) 0)) {
        return 0;
    }
    timeout = timeout <= 0 ? INT_MAX : timeout;
    int32_t i = (int32_t) sw_atomic_sub_fetch(atomic, 1);
    while (timeout > 0) {
        if ((int32_t) *atomic > i) {
            return 0;
        } else {
            usleep(1000);
            timeout -= 0.001;
        }
    }
    sw_atomic_fetch_add(atomic, 1);
    return -1;
}

int sw_atomic_futex_wakeup(sw_atomic_t *atomic, int n) {
    if (1 == (int32_t) *atomic) {
        return 0;
    }
    sw_atomic_fetch_add(atomic, n);
    return 0;
}
#endif

/* {{{ DJBX33A (Daniel J. Bernstein, Times 33 with Addition)
 *
 * This is Daniel J. Bernstein's popular `times 33' hash function as
 * posted by him years ago on comp->lang.c. It basically uses a function
 * like ``hash(i) = hash(i-1) * 33 + str[i]''. This is one of the best
 * known hash functions for strings. Because it is both computed very
 * fast and distributes very well.
 *
 * The magic of number 33, i.e. why it works better than many other
 * constants, prime or not, has never been adequately explained by
 * anyone. So I try an explanation: if one experimentally tests all
 * multipliers between 1 and 256 (as RSE did now) one detects that even
 * numbers are not useable at all. The remaining 128 odd numbers
 * (except for the number 1) work more or less all equally well. They
 * all distribute in an acceptable way and this way fill a hash table
 * with an average percent of approx. 86%.
 *
 * If one compares the Chi^2 values of the variants, the number 33 not
 * even has the best value. But the number 33 and a few other equally
 * good numbers like 17, 31, 63, 127 and 129 have nevertheless a great
 * advantage to the remaining numbers in the large set of possible
 * multipliers: their multiply operation can be replaced by a faster
 * operation based on just one shift plus either a single addition
 * or subtraction operation. And because a hash function has to both
 * distribute good _and_ has to be very fast to compute, those few
 * numbers should be preferred and seems to be the reason why Daniel J.
 * Bernstein also preferred it.
 *
 *                  -- Ralf S. Engelschall <rse@engelschall.com>
 */
uint64_t swoole_hash_php(const char *key, size_t len) {
    ulong_t hash = 5381;
    /* variant with the hash unrolled eight times */
    for (; len >= 8; len -= 8) {
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
    }

    switch (len) {
    case 7:
        hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
    /* no break */
    case 6:
        hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
    /* no break */
    case 5:
        hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
    /* no break */
    case 4:
        hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
    /* no break */
    case 3:
        hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
    /* no break */
    case 2:
        hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
    /* no break */
    case 1:
        hash = ((hash << 5) + hash) + *key++;
        break;
    case 0:
        break;
    default:
        break;
    }
    return hash;
}

#define HASH_JEN_MIX(a, b, c)                                                                                          \
    do {                                                                                                               \
        a -= b;                                                                                                        \
        a -= c;                                                                                                        \
        a ^= (c >> 13);                                                                                                \
        b -= c;                                                                                                        \
        b -= a;                                                                                                        \
        b ^= (a << 8);                                                                                                 \
        c -= a;                                                                                                        \
        c -= b;                                                                                                        \
        c ^= (b >> 13);                                                                                                \
        a -= b;                                                                                                        \
        a -= c;                                                                                                        \
        a ^= (c >> 12);                                                                                                \
        b -= c;                                                                                                        \
        b -= a;                                                                                                        \
        b ^= (a << 16);                                                                                                \
        c -= a;                                                                                                        \
        c -= b;                                                                                                        \
        c ^= (b >> 5);                                                                                                 \
        a -= b;                                                                                                        \
        a -= c;                                                                                                        \
        a ^= (c >> 3);                                                                                                 \
        b -= c;                                                                                                        \
        b -= a;                                                                                                        \
        b ^= (a << 10);                                                                                                \
        c -= a;                                                                                                        \
        c -= b;                                                                                                        \
        c ^= (b >> 15);                                                                                                \
    } while (0)

/**
 * MurmurHash2(Austin Appleby)
 */
uint64_t swoole_hash_jenkins(const char *key, size_t keylen) {
    unsigned j;
    uint64_t hashv = 0xfeedbeef;
    unsigned i = j = 0x9e3779b9;
    auto k = (unsigned) (keylen);

    while (k >= 12) {
        i += (key[0] + ((unsigned) key[1] << 8) + ((unsigned) key[2] << 16) + ((unsigned) key[3] << 24));
        j += (key[4] + ((unsigned) key[5] << 8) + ((unsigned) key[6] << 16) + ((unsigned) key[7] << 24));
        hashv += (key[8] + ((unsigned) key[9] << 8) + ((unsigned) key[10] << 16) + ((unsigned) key[11] << 24));

        HASH_JEN_MIX(i, j, hashv);

        key += 12;
        k -= 12;
    }
    hashv += keylen;
    switch (k) {
    case 11:
        hashv += ((unsigned) key[10] << 24);
        /* no break */
    case 10:
        hashv += ((unsigned) key[9] << 16);
        /* no break */
    case 9:
        hashv += ((unsigned) key[8] << 8);
        /* no break */
    case 8:
        j += ((unsigned) key[7] << 24);
        /* no break */
    case 7:
        j += ((unsigned) key[6] << 16);
        /* no break */
    case 6:
        j += ((unsigned) key[5] << 8);
        /* no break */
    case 5:
        j += key[4];
        /* no break */
    case 4:
        i += ((unsigned) key[3] << 24);
        /* no break */
    case 3:
        i += ((unsigned) key[2] << 16);
        /* no break */
    case 2:
        i += ((unsigned) key[1] << 8);
        /* no break */
    case 1:
        i += key[0];
    }
    HASH_JEN_MIX(i, j, hashv);
    return hashv;
}

/**
 * MurmurHash2(Austin Appleby)
 */
uint64_t swoole_hash_austin(const char *key, size_t keylen) {
    uint64_t h = 0 ^ keylen;

    while (keylen >= 4) {
        uint64_t k = key[0];
        k |= key[1] << 8;
        k |= key[2] << 16;
        k |= key[3] << 24;

        k *= 0x5bd1e995;
        k ^= k >> 24;
        k *= 0x5bd1e995;

        h *= 0x5bd1e995;
        h ^= k;

        key += 4;
        keylen -= 4;
    }

    switch (keylen) {
    case 3:
        h ^= key[2] << 16;
        /* no break */
    case 2:
        h ^= key[1] << 8;
        /* no break */
    case 1:
        h ^= key[0];
        h *= 0x5bd1e995;
    }

    h ^= h >> 13;
    h *= 0x5bd1e995;
    h ^= h >> 15;

    return h;
}
