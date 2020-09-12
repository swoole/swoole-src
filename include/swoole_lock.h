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

#pragma once

#include "swoole.h"

enum swLock_type {
    SW_RWLOCK = 1,
    SW_FILELOCK = 2,
    SW_MUTEX = 3,
    SW_SEM = 4,
    SW_SPINLOCK = 5,
    SW_ATOMLOCK = 6,
};

struct swMutex {
    pthread_mutex_t _lock;
    pthread_mutexattr_t attr;
};

enum swMutex_flag {
    SW_MUTEX_PROCESS_SHARED = 1,
    SW_MUTEX_ROBUST = 2,
};

#ifdef HAVE_RWLOCK
struct swRWLock {
    pthread_rwlock_t _lock;
    pthread_rwlockattr_t attr;
};
#endif

struct swLock {
    int type;
    union {
        swMutex mutex;
#ifdef HAVE_RWLOCK
        swRWLock rwlock;
#endif
#ifdef HAVE_SPINLOCK
        pthread_spinlock_t spin_lock;
#endif
        sw_atomic_t atomic_lock;
    } object;

    int (*lock_rd)(swLock *);
    int (*lock)(swLock *);
    int (*unlock)(swLock *);
    int (*trylock_rd)(swLock *);
    int (*trylock)(swLock *);
    int (*free)(swLock *);
};

// Thread Condition
struct swCond {
    swLock _lock;
    pthread_cond_t _cond;

    int (*wait)(swCond *object);
    int (*timewait)(swCond *object, long, long);
    int (*notify)(swCond *object);
    int (*broadcast)(swCond *object);
    void (*free)(swCond *object);
    int (*lock)(swCond *object);
    int (*unlock)(swCond *object);
};

int swAtomicLock_create(swLock *object);
int swMutex_create(swLock *lock, int use_in_process);
int swMutex_lockwait(swLock *lock, int timeout_msec);
int swCond_create(swCond *cond);

#ifdef HAVE_RWLOCK
int swRWLock_create(swLock *lock, int use_in_process);
#endif

#ifdef HAVE_SPINLOCK
int swSpinLock_create(swLock *object, int spin);
#endif
