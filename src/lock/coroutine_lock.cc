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
#include "swoole_lock.h"

#ifdef HAVE_IOURING_FUTEX

using swoole::AsyncIouring;
using swoole::Coroutine;
using swoole::coroutine::futex;

namespace swoole {

CoroutineLock::CoroutineLock() : Lock() {
    type_ = COROUTINE_LOCK;
    value = (sw_atomic_t *) sw_shm_malloc(sizeof(sw_atomic_t));
    *value = 0;
}

CoroutineLock::~CoroutineLock() {
    sw_shm_free((void *) value);
    value = nullptr;
}

int CoroutineLock::lock() {
    return start_lock(true);
}

int CoroutineLock::trylock() {
    return start_lock(false);
}

int CoroutineLock::lock_rd() {
    return start_lock(true);
}

int CoroutineLock::trylock_rd() {
    return start_lock(false);
}

int CoroutineLock::unlock() {
    if (*value == 0) {
        return 0;
    }

    *value = 0;
    current_coroutine = nullptr;

    int count =
        futex(AsyncIouring::SW_IORING_OP_FUTEX_WAKE, (uint32_t *) value, 1, FUTEX_BITSET_MATCH_ANY, FUTEX2_SIZE_U32, 0);
    return count > 0 ? 0 : 1;
}

int CoroutineLock::start_lock(bool blocking) {
    Coroutine *coroutine = Coroutine::get_current();
    if (current_coroutine == coroutine) {
        return 0;
    }

    int result = 0;
    if (!sw_atomic_cmp_set(value, 0, 1)) {
        if (!blocking) {
            return 1;
        }

        result = futex(
            AsyncIouring::SW_IORING_OP_FUTEX_WAIT, (uint32_t *) value, 1, FUTEX_BITSET_MATCH_ANY, FUTEX2_SIZE_U32, 0);
        *value = 1;
    }

    current_coroutine = coroutine;
    return result;
}
}  // namespace swoole
#endif
