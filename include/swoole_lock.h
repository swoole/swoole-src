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
        MUTEX = 3,
        SPIN_LOCK = 5,
        COROUTINE_LOCK = 6,
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

class CoroutineLock : public Lock {
  private:
    long cid = 0;
    sw_atomic_t *value = nullptr;
    void *coroutine = nullptr;

    int lock_impl(bool blocking = true);

  public:
    CoroutineLock();
    ~CoroutineLock();
    int lock_rd() override;
    int lock() override;
    int unlock() override;
    int trylock_rd() override;
    int trylock() override;
};

#if defined(HAVE_PTHREAD_BARRIER) && !(defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__))
#define SW_USE_PTHREAD_BARRIER
#endif

struct Barrier {
#ifdef SW_USE_PTHREAD_BARRIER
    pthread_barrier_t barrier_;
    pthread_barrierattr_t barrier_attr_;
    bool shared_;
#else
    sw_atomic_t count_;
    sw_atomic_t barrier_;
#endif
    void init(bool shared, int count);
    void wait();
    void destroy();
};

}  // namespace swoole
