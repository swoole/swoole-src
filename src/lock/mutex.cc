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
  +----------------------------------------------------------------------+
*/

#include "swoole_lock.h"

static int swMutex_lock(swLock *lock);
static int swMutex_unlock(swLock *lock);
static int swMutex_trylock(swLock *lock);
static int swMutex_free(swLock *lock);

int swMutex_create(swLock *lock, int flags) {
    int ret;
    sw_memset_zero(lock, sizeof(swLock));
    lock->type = SW_MUTEX;
    pthread_mutexattr_init(&lock->object.mutex.attr);
    if (flags & SW_MUTEX_PROCESS_SHARED) {
        pthread_mutexattr_setpshared(&lock->object.mutex.attr, PTHREAD_PROCESS_SHARED);
    }

    if (flags & SW_MUTEX_ROBUST) {
#ifdef HAVE_PTHREAD_MUTEXATTR_SETROBUST
        pthread_mutexattr_setrobust(&lock->object.mutex.attr, PTHREAD_MUTEX_ROBUST);
#else
        swWarn("PTHREAD_MUTEX_ROBUST is not supported");
#endif
    }

    if ((ret = pthread_mutex_init(&lock->object.mutex._lock, &lock->object.mutex.attr)) < 0) {
        return SW_ERR;
    }
    lock->lock = swMutex_lock;
    lock->unlock = swMutex_unlock;
    lock->trylock = swMutex_trylock;
    lock->free = swMutex_free;
    return SW_OK;
}

static int swMutex_lock(swLock *lock) {
    int retval = pthread_mutex_lock(&lock->object.mutex._lock);
#ifdef HAVE_PTHREAD_MUTEX_CONSISTENT
    if (retval == EOWNERDEAD) {
        retval = pthread_mutex_consistent(&lock->object.mutex._lock);
    }
#endif
    return retval;
}

static int swMutex_unlock(swLock *lock) {
    return pthread_mutex_unlock(&lock->object.mutex._lock);
}

static int swMutex_trylock(swLock *lock) {
    return pthread_mutex_trylock(&lock->object.mutex._lock);
}

#ifdef HAVE_MUTEX_TIMEDLOCK
int swMutex_lockwait(swLock *lock, int timeout_msec) {
    struct timespec timeo;
    timeo.tv_sec = timeout_msec / 1000;
    timeo.tv_nsec = (timeout_msec - timeo.tv_sec * 1000) * 1000 * 1000;
    return pthread_mutex_timedlock(&lock->object.mutex._lock, &timeo);
}
#else
int swMutex_lockwait(swLock *lock, int timeout_msec) {
    int sub = 1;
    int sleep_ms = 1000;

    if (timeout_msec > 100) {
        sub = 10;
        sleep_ms = 10000;
    }

    while (timeout_msec > 0) {
        if (pthread_mutex_trylock(&lock->object.mutex._lock) == 0) {
            return 0;
        } else {
            usleep(sleep_ms);
            timeout_msec -= sub;
        }
    }
    return ETIMEDOUT;
}
#endif

static int swMutex_free(swLock *lock) {
    pthread_mutexattr_destroy(&lock->object.mutex.attr);
    return pthread_mutex_destroy(&lock->object.mutex._lock);
}
