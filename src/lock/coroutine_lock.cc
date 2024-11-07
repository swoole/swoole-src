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
  | Author: NathanFreeman  <mariasocute@163.com>                         |
  +----------------------------------------------------------------------+
 */

#include "swoole.h"

#ifdef HAVE_IOURING_FUTEX
#include "swoole_iouring.h"
#else
#include "swoole_coroutine_system.h"
using swoole::coroutine::System;
#endif

#include "swoole_lock.h"

namespace swoole {
CoroutineLock::CoroutineLock() : Lock() {
    type_ = COROUTINE_LOCK;
    value = (sw_atomic_t *) sw_mem_pool()->alloc(sizeof(sw_atomic_t));
    *value = 0;
}

CoroutineLock::~CoroutineLock() {
    sw_mem_pool()->free((void *) value);
    value = nullptr;
}

int CoroutineLock::lock() {
    return lock_impl(true);
}

int CoroutineLock::trylock() {
    return lock_impl(false);
}

int CoroutineLock::lock_rd() {
    return lock_impl(true);
}

int CoroutineLock::trylock_rd() {
    return lock_impl(false);
}

int CoroutineLock::unlock() {
    Coroutine *current_coroutine = Coroutine::get_current();
    if (current_coroutine == nullptr) {
        swoole_warning("The coroutine lock can only be used in a coroutine environment");
        return SW_ERROR_CO_OUT_OF_COROUTINE;
    }

    if (*value == 0) {
        return 0;
    }

    *value = 0;
    cid = 0;
    coroutine = nullptr;

#ifdef HAVE_IOURING_FUTEX
    return Iouring::futex_wakeup((uint32_t *) value) >= 0 ? 0 : errno;
#else
    return 0;
#endif
}

int CoroutineLock::lock_impl(bool blocking) {
    Coroutine *current_coroutine = Coroutine::get_current();
    if (current_coroutine == nullptr) {
        swoole_warning("The coroutine lock can only be used in a coroutine environment");
        return SW_ERROR_CO_OUT_OF_COROUTINE;
    }

    if (current_coroutine == static_cast<Coroutine *>(coroutine) && current_coroutine->get_cid() == cid) {
        return 0;
    }

    int result = 0;
#ifndef HAVE_IOURING_FUTEX
    double second = 0.001;
#endif

    while (true) {
        if (sw_atomic_cmp_set(value, 0, 1)) {
            break;
        }

        if (!blocking) {
            return EBUSY;
        }

#ifdef HAVE_IOURING_FUTEX
        result = Iouring::futex_wait((uint32_t *) value);
        if (result != 0) {
            return errno;
        }
#else
        if (System::sleep(second) != SW_OK) {
            return SW_ERROR_CO_CANCELED;
        }
        second *= 2;
#endif
    }

    cid = current_coroutine->get_cid();
    coroutine = (void *) current_coroutine;
    return result;
}
}  // namespace swoole
