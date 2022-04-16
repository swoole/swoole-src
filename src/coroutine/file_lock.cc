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

using swoole::Coroutine;

class LockManager {
  public:
    bool lock_ex = false;
    bool lock_sh = false;
    std::queue<Coroutine *> queue_;
};

static std::unordered_map<std::string, LockManager *> lock_pool;

static inline LockManager *get_manager(const char *filename) {
    std::string key(filename);
    auto i = lock_pool.find(key);
    LockManager *lm;
    if (i == lock_pool.end()) {
        lm = new LockManager;
        lock_pool[key] = lm;
    } else {
        lm = i->second;
    }
    return lm;
}

static inline int lock_ex(const char *filename, int fd) {
    LockManager *lm = get_manager(filename);
    if (lm->lock_ex || lm->lock_sh) {
        Coroutine *co = Coroutine::get_current();
        lm->queue_.push(co);
        co->yield();
    }
    lm->lock_ex = true;
    if (swoole_coroutine_flock(fd, LOCK_EX) < 0) {
        lm->lock_ex = false;
        return -1;
    } else {
        return 0;
    }
}

static inline int lock_sh(const char *filename, int fd) {
    LockManager *lm = get_manager(filename);
    if (lm->lock_ex) {
        Coroutine *co = Coroutine::get_current();
        lm->queue_.push(co);
        co->yield();
    }
    lm->lock_sh = true;
    if (swoole_coroutine_flock(fd, LOCK_SH) < 0) {
        lm->lock_sh = false;
        return -1;
    } else {
        return 0;
    }
}

static inline int lock_release(const char *filename, int fd) {
    std::string key(filename);
    auto i = lock_pool.find(key);
    if (i == lock_pool.end()) {
        return swoole_coroutine_flock(fd, LOCK_UN);
    }
    LockManager *lm = i->second;
    if (lm->queue_.empty()) {
        delete lm;
        lock_pool.erase(i);
        return swoole_coroutine_flock(fd, LOCK_UN);
    } else {
        Coroutine *co = lm->queue_.front();
        lm->queue_.pop();
        int retval = swoole_coroutine_flock(fd, LOCK_UN);
        co->resume();
        return retval;
    }
}

#ifdef LOCK_NB
static inline int lock_nb(const char *filename, int fd, int operation) {
    int retval = ::flock(fd, operation | LOCK_NB);
    if (retval == 0) {
        LockManager *lm = get_manager(filename);
        if (operation == LOCK_EX) {
            lm->lock_ex = true;
        } else {
            lm->lock_sh = true;
        }
    }
    return retval;
}
#endif

int swoole_coroutine_flock_ex(const char *filename, int fd, int operation) {
    Coroutine *co = Coroutine::get_current();
    if (sw_unlikely(SwooleTG.reactor == nullptr || !co)) {
        return ::flock(fd, operation);
    }

    const char *real = realpath(filename, sw_tg_buffer()->str);
    if (real == nullptr) {
        errno = ENOENT;
        swoole_set_last_error(ENOENT);
        return -1;
    }

    switch (operation) {
    case LOCK_EX:
        return lock_ex(real, fd);
    case LOCK_SH:
        return lock_sh(real, fd);
    case LOCK_UN:
        return lock_release(real, fd);
    default:
#ifdef LOCK_NB
        if (operation & LOCK_NB) {
            return lock_nb(real, fd, operation & (~LOCK_NB));
        }
#endif
        return -1;
    }

    return 0;
}
