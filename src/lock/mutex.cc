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

namespace swoole {

struct MutexImpl {
    pthread_mutex_t lock_;
    pthread_mutexattr_t attr_;
};

Mutex::Mutex(int flags) : Lock() {
    flags_ = flags;

    if (flags & PROCESS_SHARED) {
        impl = (MutexImpl *) sw_mem_pool()->alloc(sizeof(*impl));
        if (impl == nullptr) {
            throw std::bad_alloc();
        }
        shared_ = true;
    } else {
        impl = new MutexImpl();
        shared_ = false;
    }

    type_ = MUTEX;
    pthread_mutexattr_init(&impl->attr_);

    if (flags & PROCESS_SHARED) {
#ifdef HAVE_PTHREAD_MUTEXATTR_SETPSHARED
        pthread_mutexattr_setpshared(&impl->attr_, PTHREAD_PROCESS_SHARED);
#else
        swoole_warning("PTHREAD_MUTEX_PSHARED is not supported");
#endif
    }

    if (flags & ROBUST) {
#ifdef HAVE_PTHREAD_MUTEXATTR_SETROBUST
        pthread_mutexattr_setrobust(&impl->attr_, PTHREAD_MUTEX_ROBUST);
#else
        swoole_warning("PTHREAD_MUTEX_ROBUST is not supported");
#endif
    }

    if (pthread_mutex_init(&impl->lock_, &impl->attr_) != 0) {
        throw std::system_error(errno, std::generic_category(), "pthread_mutex_init() failed");
    }
}

int Mutex::lock() {
    int retval = pthread_mutex_lock(&impl->lock_);

#ifdef HAVE_PTHREAD_MUTEX_CONSISTENT
    if (retval == EOWNERDEAD && (flags_ & ROBUST)) {
        retval = pthread_mutex_consistent(&impl->lock_);
    }
#endif

    return retval;
}

int Mutex::lock_rd() {
    return lock();
}

int Mutex::unlock() {
    return pthread_mutex_unlock(&impl->lock_);
}

int Mutex::trylock() {
    return pthread_mutex_trylock(&impl->lock_);
}

int Mutex::trylock_rd() {
    return trylock();
}

#ifdef HAVE_MUTEX_TIMEDLOCK
int Mutex::lock_wait(int timeout_msec) {
    struct timespec timeo = swoole_time_until(timeout_msec);
    return pthread_mutex_timedlock(&impl->lock_, &timeo);
}
#else
int Mutex::lock_wait(int timeout_msec) {
    int sub = 1;
    int sleep_ms = 1000;

    if (timeout_msec > 100) {
        sub = 10;
        sleep_ms = 10000;
    }

    while (timeout_msec > 0) {
        if (pthread_mutex_trylock(&impl->lock_) == 0) {
            return 0;
        } else {
            usleep(sleep_ms);
            timeout_msec -= sub;
        }
    }
    return ETIMEDOUT;
}
#endif

Mutex::~Mutex() {
    pthread_mutexattr_destroy(&impl->attr_);
    pthread_mutex_destroy(&impl->lock_);
    if (shared_) {
        sw_mem_pool()->free(impl);
    } else {
        delete impl;
    }
}

}  // namespace swoole
