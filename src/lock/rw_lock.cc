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
#include "swoole_lock.h"

#ifdef HAVE_RWLOCK

namespace swoole {

struct RWLockImpl {
    pthread_rwlock_t lock_;
    pthread_rwlockattr_t attr_;
};

RWLock::RWLock(bool shared) : Lock(RW_LOCK, shared) {
    if (shared) {
        impl = (RWLockImpl *) sw_mem_pool()->alloc(sizeof(*impl));
        if (impl == nullptr) {
            throw std::bad_alloc();
        }
    } else {
        impl = new RWLockImpl();
    }

    pthread_rwlockattr_init(&impl->attr_);
    if (shared) {
        pthread_rwlockattr_setpshared(&impl->attr_, PTHREAD_PROCESS_SHARED);
    }
    if (pthread_rwlock_init(&impl->lock_, &impl->attr_) != 0) {
        throw std::system_error(errno, std::generic_category(), "pthread_rwlock_init() failed");
    }
}

static int rwlock_timed_lock_rd(pthread_rwlock_t *rwlock, int timeout_msec) {
#ifdef HAVE_RWLOCK_TIMEDRDLOCK
    timespec timeo;
    realtime_get(&timeo);
    realtime_add(&timeo, timeout_msec);
    return pthread_rwlock_timedrdlock(rwlock, &timeo);
#else
    return sw_wait_for([rwlock]() { return pthread_rwlock_tryrdlock(rwlock) == 0; }, timeout_msec) ? 0 : ETIMEDOUT;
#endif
}

static int rwlock_timed_lock_wr(pthread_rwlock_t *rwlock, int timeout_msec) {
#ifdef HAVE_RWLOCK_TIMEDRDLOCK
    timespec timeo;
    realtime_get(&timeo);
    realtime_add(&timeo, timeout_msec);
    return pthread_rwlock_timedwrlock(rwlock, &timeo);
#else
    return sw_wait_for([rwlock]() { return pthread_rwlock_trywrlock(rwlock) == 0; }, timeout_msec) ? 0 : ETIMEDOUT;
#endif
}

int RWLock::lock(int operation, int timeout_msec) {
    if (operation & LOCK_NB) {
        if (operation & LOCK_SH) {
            return pthread_rwlock_tryrdlock(&impl->lock_);
        } else {
            return pthread_rwlock_trywrlock(&impl->lock_);
        }
    } else {
        if (timeout_msec > 0) {
            if (operation & LOCK_SH) {
                return rwlock_timed_lock_rd(&impl->lock_, timeout_msec);
            } else {
                return rwlock_timed_lock_wr(&impl->lock_, timeout_msec);
            }
        } else {
            if (operation & LOCK_SH) {
                return pthread_rwlock_rdlock(&impl->lock_);
            } else {
                return pthread_rwlock_wrlock(&impl->lock_);
            }
        }
    }
}

int RWLock::unlock() {
    return pthread_rwlock_unlock(&impl->lock_);
}

RWLock::~RWLock() {
    pthread_rwlockattr_destroy(&impl->attr_);
    pthread_rwlock_destroy(&impl->lock_);
    if (shared_) {
        sw_mem_pool()->free(impl);
    } else {
        delete impl;
    }
}

}  // namespace swoole
#endif
