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

#ifdef HAVE_SPINLOCK

namespace swoole {

SpinLock::SpinLock(int use_in_process) : Lock() {
    if (use_in_process) {
        impl = (pthread_spinlock_t *) sw_mem_pool()->alloc(sizeof(*impl));
        if (impl == nullptr) {
            throw std::bad_alloc();
        }
        shared_ = true;
    } else {
        impl = new pthread_spinlock_t();
        shared_ = false;
    }

    type_ = SPIN_LOCK;
    if (pthread_spin_init(impl, use_in_process) != 0) {
        throw std::system_error(errno, std::generic_category(), "pthread_spin_init() failed");
    }
}

int SpinLock::lock() {
    return pthread_spin_lock(impl);
}

int SpinLock::lock_rd() {
    return lock();
}

int SpinLock::unlock() {
    return pthread_spin_unlock(impl);
}

int SpinLock::trylock() {
    return pthread_spin_trylock(impl);
}

int SpinLock::trylock_rd() {
    return trylock();
}

SpinLock::~SpinLock() {
    pthread_spin_destroy(impl);
    if (shared_) {
        sw_mem_pool()->free((void *) impl);
    } else {
        delete impl;
    }
}
}  // namespace swoole
#endif
