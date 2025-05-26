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

#include <sys/file.h>

#include <queue>

#include "swoole_coroutine.h"
#include "swoole_coroutine_c_api.h"
#include "swoole_coroutine_system.h"

using swoole::Coroutine;
using swoole::coroutine::async;
using swoole::coroutine::wait_for;

#ifdef LOCK_NB
static inline int do_lock(int fd, int operation) {
    int retval = 0;
    auto success = wait_for([&retval, operation, fd]() {
        auto rv = flock(fd, operation | LOCK_NB);
        if (rv == 0) {
            retval = 0;
        } else if (rv == -1 && errno == EWOULDBLOCK) {
            return false;
        } else {
            retval = -1;
        }
        return true;
    });
    return success ? retval : -1;
}

static inline int lock_ex(int fd) {
    return do_lock(fd, LOCK_EX);
}

static inline int lock_sh(int fd) {
    return do_lock(fd, LOCK_SH);
}

static inline int lock_release(int fd) {
    return flock(fd, LOCK_UN);
}
#endif

int swoole_coroutine_flock(int fd, int operation) {
    Coroutine *co = Coroutine::get_current();
    if (sw_unlikely(SwooleTG.reactor == nullptr || !co)) {
        return ::flock(fd, operation);
    }

#ifndef LOCK_NB
    int retval = -1;
    async([&]() { retval = flock(fd, operation); });
    return retval;
#else
    if (operation & LOCK_NB) {
        return ::flock(fd, operation);
    }
    switch (operation) {
    case LOCK_EX:
        return lock_ex(fd);
    case LOCK_SH:
        return lock_sh(fd);
    case LOCK_UN:
        return lock_release(fd);
    default:
        break;
    }
    errno = EINVAL;
    swoole_set_last_error(EINVAL);
    return -1;
#endif
}
