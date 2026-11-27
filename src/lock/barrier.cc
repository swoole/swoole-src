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

#define BARRIER_USEC 10000

void Barrier::init(bool shared, int count) {
#ifdef SW_USE_PTHREAD_BARRIER
    if (shared) {
        pthread_barrierattr_init(&barrier_attr_);
        pthread_barrierattr_setpshared(&barrier_attr_, PTHREAD_PROCESS_SHARED);
        pthread_barrier_init(&barrier_, &barrier_attr_, count);
    } else {
        pthread_barrier_init(&barrier_, nullptr, count);
    }
    shared_ = shared;
#else
    barrier_ = 0;
    count_ = count;
    generation_ = 0;
#endif
}

void Barrier::wait() {
#ifdef SW_USE_PTHREAD_BARRIER
    pthread_barrier_wait(&barrier_);
#else
    const uint32_t generation = sw_atomic_load_acquire(&generation_);
    if (sw_atomic_add_fetch(&barrier_, 1) == count_) {
        // The final arrival observes preceding arrivals through the atomic counter. Reset it before
        // publishing completion, so a fast participant can safely arrive again in the next generation.
        sw_atomic_store_release(&barrier_, 0);
        sw_atomic_store_release(&generation_, generation + 1);
        return;
    }
    // Wait for this generation, not the arrival count: that count can already belong to the next round.
    // Acquiring completion also makes every participant's writes before wait() visible after it returns.
    while (sw_atomic_load_acquire(&generation_) == generation) {
        sw_usleep(BARRIER_USEC);
    }
#endif
}

void Barrier::destroy() {
#ifdef SW_USE_PTHREAD_BARRIER
    pthread_barrier_destroy(&barrier_);
    if (shared_) {
        pthread_barrierattr_destroy(&barrier_attr_);
    }
#endif
}

};  // namespace swoole
