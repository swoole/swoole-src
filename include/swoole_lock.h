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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"
#include "swoole_memory.h"

#include <system_error>

namespace swoole {

class Lock {
  public:
    enum Type {
        NONE,
        RW_LOCK = 1,
        FILE_LOCK = 2,
        MUTEX = 3,
        SEM = 4,
        SPIN_LOCK = 5,
        ATOMIC_LOCK = 6,
    };
    Type get_type() {
        return type_;
    }
    virtual ~Lock(){};
    virtual int lock_rd() = 0;
    virtual int lock() = 0;
    virtual int unlock() = 0;
    virtual int trylock_rd() = 0;
    virtual int trylock() = 0;

  protected:
    Lock() {
        type_ = NONE;
        shared_ = false;
    }
    enum Type type_;
    bool shared_;
};

struct MutexImpl;

class Mutex : public Lock {
    MutexImpl *impl;
    int flags_;

  public:
    enum Flag {
        PROCESS_SHARED = 1,
        ROBUST = 2,
    };

    Mutex(int flags);
    ~Mutex();
    int lock_rd() override;
    int lock() override;
    int unlock() override;
    int trylock_rd() override;
    int trylock() override;
    int lock_wait(int timeout_msec);
};

#ifdef HAVE_RWLOCK
struct RWLockImpl;

class RWLock : public Lock {
    RWLockImpl *impl;

  public:
    RWLock(int use_in_process);
    ~RWLock();
    int lock_rd() override;
    int lock() override;
    int unlock() override;
    int trylock_rd() override;
    int trylock() override;
};
#endif

#ifdef HAVE_SPINLOCK
class SpinLock : public Lock {
    pthread_spinlock_t *impl;

  public:
    SpinLock(int use_in_process);
    ~SpinLock();
    int lock_rd() override;
    int lock() override;
    int unlock() override;
    int trylock_rd() override;
    int trylock() override;
};
#endif
}  // namespace swoole
