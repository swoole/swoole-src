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

#include "swoole_lock.h"

#ifdef HAVE_RWLOCK

namespace swoole {
#ifdef _WIN32
struct RWLockImpl {
    CRITICAL_SECTION cs;
    CONDITION_VARIABLE cv_read;
    CONDITION_VARIABLE cv_write;
    int readers;
    int writers;
    int write_waiters;
    bool shared;

    RWLockImpl(bool shared_flag) : readers(0), writers(0), write_waiters(0), shared(shared_flag) {
        InitializeCriticalSection(&cs);
        InitializeConditionVariable(&cv_read);
        InitializeConditionVariable(&cv_write);
    }

    ~RWLockImpl() {
        DeleteCriticalSection(&cs);
    }
};

static int rwlock_timed_lock_rd(RWLockImpl* impl, int timeout_msec) {
    EnterCriticalSection(&impl->cs);
    while (impl->writers > 0 || impl->write_waiters > 0) {
        if (timeout_msec == 0) {
            LeaveCriticalSection(&impl->cs);
            return EBUSY;
        }
        if (timeout_msec > 0) {
            BOOL ok = SleepConditionVariableCS(&impl->cv_read, &impl->cs, timeout_msec);
            if (!ok) {
                DWORD err = GetLastError();
                LeaveCriticalSection(&impl->cs);
                return (err == 1460L /* ERROR_TIMEOUT */) ? ETIMEDOUT : EAGAIN;
            }
        } else {
            SleepConditionVariableCS(&impl->cv_read, &impl->cs, INFINITE);
        }
    }
    impl->readers++;
    LeaveCriticalSection(&impl->cs);
    return 0;
}

static int rwlock_timed_lock_wr(RWLockImpl* impl, int timeout_msec) {
    EnterCriticalSection(&impl->cs);
    impl->write_waiters++;
    while (impl->readers > 0 || impl->writers > 0) {
        if (timeout_msec == 0) {
            impl->write_waiters--;
            LeaveCriticalSection(&impl->cs);
            return EBUSY;
        }
        if (timeout_msec > 0) {
            BOOL ok = SleepConditionVariableCS(&impl->cv_write, &impl->cs, timeout_msec);
            if (!ok) {
                DWORD err = GetLastError();
                impl->write_waiters--;
                LeaveCriticalSection(&impl->cs);
                return (err == SW_WIN32_ERROR_TIMEOUT) ? ETIMEDOUT : EAGAIN;
            }
        } else {
            SleepConditionVariableCS(&impl->cv_write, &impl->cs, INFINITE);
        }
    }
    impl->write_waiters--;
    impl->writers = 1;
    LeaveCriticalSection(&impl->cs);
    return 0;
}

RWLock::RWLock(bool shared) : Lock(RW_LOCK, shared) {
    if (shared) {
        throw std::invalid_argument("SRWLock does not support process-shared mode on Windows");
    } else {
        impl = new RWLockImpl(shared);
    }
}

int RWLock::lock(int operation, int timeout_msec) {
    bool nonblock = (operation & LOCK_NB) != 0;
    bool shared = (operation & LOCK_SH) != 0;

    if (nonblock) {
        if (shared) {
            EnterCriticalSection(&impl->cs);
            if (impl->writers > 0 || impl->write_waiters > 0) {
                LeaveCriticalSection(&impl->cs);
                return EBUSY;
            }
            impl->readers++;
            LeaveCriticalSection(&impl->cs);
            return 0;
        } else {
            EnterCriticalSection(&impl->cs);
            if (impl->readers > 0 || impl->writers > 0) {
                LeaveCriticalSection(&impl->cs);
                return EBUSY;
            }
            impl->writers = 1;
            LeaveCriticalSection(&impl->cs);
            return 0;
        }
    } else {
        if (shared) {
            return rwlock_timed_lock_rd(impl, timeout_msec);
        } else {
            return rwlock_timed_lock_wr(impl, timeout_msec);
        }
    }
}

int RWLock::unlock() {
    EnterCriticalSection(&impl->cs);
    if (impl->writers > 0) {
        impl->writers = 0;
        if (impl->write_waiters > 0) {
            WakeConditionVariable(&impl->cv_write);
        } else {
            WakeAllConditionVariable(&impl->cv_read);
        }
    } else if (impl->readers > 0) {
        impl->readers--;
        if (impl->readers == 0 && impl->write_waiters > 0) {
            WakeConditionVariable(&impl->cv_write);
        }
    }
    LeaveCriticalSection(&impl->cs);
    return 0;
}

RWLock::~RWLock() {
    if (impl) {
        delete impl;
        impl = nullptr;
    }
}
#else
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
        pthread_rwlockattr_destroy(&impl->attr_);
        free_ptr(impl);
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
    free_ptr(impl);
}

#endif
}  // namespace swoole
#endif
