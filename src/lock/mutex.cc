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

namespace swoole {

#ifdef _WIN32
struct MutexImpl {
    SRWLOCK lock_;
    bool exclusive_;
};

Mutex::Mutex(bool shared) : Lock(MUTEX, shared) {
    if (shared) {
        impl = (MutexImpl *) sw_mem_pool()->alloc(sizeof(*impl));
        if (impl == nullptr) {
            throw std::bad_alloc();
        }
    } else {
        impl = new MutexImpl();
    }
    InitializeSRWLock(&impl->lock_);
    impl->exclusive_ = false;
}

int Mutex::lock(int operation, int timeout_msec) {
    if (operation & LOCK_NB) {
        // TryAcquireSRWLockExclusive returns TRUE if acquired
        if (TryAcquireSRWLockExclusive(&impl->lock_)) {
            impl->exclusive_ = true;
            return 0;
        }
        return EBUSY;
    }
    if (timeout_msec > 0) {
        return sw_wait_for([this]() {
            if (TryAcquireSRWLockExclusive(&impl->lock_)) {
                impl->exclusive_ = true;
                return true;
            }
            return false;
        }, timeout_msec) ? 0 : ETIMEDOUT;
    }
    AcquireSRWLockExclusive(&impl->lock_);
    impl->exclusive_ = true;
    return 0;
}

int Mutex::unlock() {
    if (impl->exclusive_) {
        ReleaseSRWLockExclusive(&impl->lock_);
        impl->exclusive_ = false;
    }
    return 0;
}

Mutex::~Mutex() {
    // SRWLOCK does not need explicit destruction
    free_ptr(impl);
}
#else
struct MutexImpl {
    pthread_mutex_t lock_;
    pthread_mutexattr_t attr_;
};

Mutex::Mutex(bool shared) : Lock(MUTEX, shared) {
    if (shared) {
        impl = (MutexImpl *) sw_mem_pool()->alloc(sizeof(*impl));
        if (impl == nullptr) {
            throw std::bad_alloc();
        }
    } else {
        impl = new MutexImpl();
    }

    int err = pthread_mutexattr_init(&impl->attr_);
    if (err != 0) {
        free_ptr(impl);
        throw std::system_error(err, std::generic_category(), "pthread_mutexattr_init() failed");
    }
    if (shared) {
        err = pthread_mutexattr_setpshared(&impl->attr_, PTHREAD_PROCESS_SHARED);
        if (err != 0) {
            pthread_mutexattr_destroy(&impl->attr_);
            free_ptr(impl);
            throw std::system_error(err, std::generic_category(), "pthread_mutexattr_setpshared() failed");
        }
    }
    err = pthread_mutex_init(&impl->lock_, &impl->attr_);
    if (err != 0) {
        pthread_mutexattr_destroy(&impl->attr_);
        free_ptr(impl);
        throw std::system_error(err, std::generic_category(), "pthread_mutex_init() failed");
    }
}

int Mutex::lock(int operation, int timeout_msec) {
    if (operation & LOCK_NB) {
        return pthread_mutex_trylock(&impl->lock_);
    }
    if (timeout_msec > 0) {
#ifdef HAVE_MUTEX_TIMEDLOCK
        timespec timeo;
        realtime_get(&timeo);
        realtime_add(&timeo, timeout_msec);
        return pthread_mutex_timedlock(&impl->lock_, &timeo);
#else
        return sw_wait_for([this]() { return pthread_mutex_trylock(&impl->lock_) == 0; }, timeout_msec) ? 0 : ETIMEDOUT;
#endif
    }
    return pthread_mutex_lock(&impl->lock_);
}

int Mutex::unlock() {
    return pthread_mutex_unlock(&impl->lock_);
}

Mutex::~Mutex() {
    pthread_mutexattr_destroy(&impl->attr_);
    pthread_mutex_destroy(&impl->lock_);
    free_ptr(impl);
}
#endif

}  // namespace swoole
