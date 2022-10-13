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
    pthread_rwlock_t _lock;
    pthread_rwlockattr_t attr;
};

RWLock::RWLock(int use_in_process) : Lock() {
    if (use_in_process) {
        impl = (RWLockImpl *) sw_mem_pool()->alloc(sizeof(*impl));
        if (impl == nullptr) {
            throw std::bad_alloc();
        }
        shared_ = true;
    } else {
        impl = new RWLockImpl();
        shared_ = false;
    }

    type_ = RW_LOCK;
    pthread_rwlockattr_init(&impl->attr);
    if (use_in_process == 1) {
        pthread_rwlockattr_setpshared(&impl->attr, PTHREAD_PROCESS_SHARED);
    }
    if (pthread_rwlock_init(&impl->_lock, &impl->attr) != 0) {
        throw std::system_error(errno, std::generic_category(), "pthread_rwlock_init() failed");
    }
}

int RWLock::lock_rd() {
    return pthread_rwlock_rdlock(&impl->_lock);
}

int RWLock::lock() {
    return pthread_rwlock_wrlock(&impl->_lock);
}

int RWLock::unlock() {
    return pthread_rwlock_unlock(&impl->_lock);
}

int RWLock::trylock_rd() {
    return pthread_rwlock_tryrdlock(&impl->_lock);
}

int RWLock::trylock() {
    return pthread_rwlock_trywrlock(&impl->_lock);
}

RWLock::~RWLock() {
    pthread_rwlockattr_destroy(&impl->attr);
    pthread_rwlock_destroy(&impl->_lock);
    if (shared_) {
        sw_mem_pool()->free(impl);
    } else {
        delete impl;
    }
}

}  // namespace swoole

#endif
