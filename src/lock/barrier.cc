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

#define BARRIER_USEC 10000

void Barrier::init(bool shared, int count) {
#ifdef SW_USE_PTHREAD_BARRIER
    if (shared) {
        pthread_barrierattr_setpshared(&barrier_attr_, PTHREAD_PROCESS_SHARED);
        pthread_barrier_init(&barrier_, &barrier_attr_, count);
    } else {
        pthread_barrier_init(&barrier_, nullptr, count);
    }
    shared_ = shared;
#else
    barrier_ = 0;
    count_ = count;
#endif
}

void Barrier::wait() {
#ifdef SW_USE_PTHREAD_BARRIER
    pthread_barrier_wait(&barrier_);
#else
    sw_atomic_add_fetch(&barrier_, 1);
    SW_LOOP {
        if (barrier_ == count_) {
            break;
        }
        usleep(BARRIER_USEC);
        sw_atomic_memory_barrier();
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
