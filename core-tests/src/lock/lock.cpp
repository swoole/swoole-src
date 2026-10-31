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
  | @link     https://www.swoole.com/                                    |
  | @contact  team@swoole.com                                            |
  | @license  https://github.com/swoole/swoole-src/blob/master/LICENSE   |
  | @Author   Tianfeng Han  <rango@swoole.com>                           |
  +----------------------------------------------------------------------+
*/

#include "test_coroutine.h"
#include "swoole_lock.h"
#include "swoole_util.h"

#include <thread>
#include <future>

using swoole::Coroutine;
using swoole::CoroutineLock;
using swoole::Lock;
using swoole::Mutex;
using swoole::RWLock;
using swoole::SpinLock;
using swoole::coroutine::System;
using swoole::test::coroutine;

static void test_func(Lock &lock) {
    int count = 0;
    const int N = 100000;

    auto fn = [&]() {
        for (int i = 0; i < N; i++) {
            ASSERT_EQ(lock.lock(), 0);
            count++;
            ASSERT_EQ(lock.unlock(), 0);
        }
    };

    std::thread t1(fn);
    std::thread t2(fn);

    t1.join();
    t2.join();

    ASSERT_EQ(count, N * 2);
}

static void test_lock_rd_func(Lock &lock) {
    ASSERT_EQ(lock.lock(LOCK_SH), 0);
    int result = -1;
    std::thread contender([&]() {
        result = lock.lock(LOCK_SH | LOCK_NB);
        if (result == 0) {
            EXPECT_EQ(lock.unlock(), 0);
        }
    });
    contender.join();
    EXPECT_EQ(lock.unlock(), 0);
    EXPECT_EQ(result, lock.get_type() == Lock::RW_LOCK ? 0 : EBUSY);
}

static void test_timed_lock_timeout(Lock &lock, int held_operation, int requested_operation) {
    ASSERT_EQ(lock.lock(held_operation), 0);
    std::promise<int> result;
    auto future = result.get_future();
    std::thread contender([&]() {
        const int error = lock.lock(requested_operation, 20);
        if (error == 0) {
            EXPECT_EQ(lock.unlock(), 0);
        }
        result.set_value(error);
    });
    // Keep the owner locked until the contender finishes. The generous watchdog
    // also releases it if a broken timed lock accidentally falls back to blocking.
    const auto status = future.wait_for(std::chrono::seconds(2));
    EXPECT_EQ(lock.unlock(), 0);
    contender.join();
    EXPECT_EQ(status, std::future_status::ready);
    EXPECT_EQ(future.get(), ETIMEDOUT);
    ASSERT_EQ(lock.lock(LOCK_EX | LOCK_NB), 0);
    EXPECT_EQ(lock.unlock(), 0);
}

static void test_share_lock_fun(Lock &lock) {
    lock.lock();
    const int sleep_us = 10000;
    int magic_num = swoole_rand(100000, 9999999);
    int *_num = (int *) sw_mem_pool()->alloc(sizeof(int));
    *_num = 0;

    pid_t pid = fork();

    if (pid == 0) {
        lock.lock();
        *_num = magic_num;
        usleep(1);
        exit(0);
    } else {
        usleep(sleep_us);
        lock.unlock();
        int status;
        pid_t _pid = waitpid(pid, &status, 0);
        if (_pid != pid) {
            swoole_warning("error pid=%d", _pid);
        }
        ASSERT_EQ(*_num, magic_num);
    }
}

TEST(lock, mutex) {
    Mutex lock(0);
    test_func(reinterpret_cast<Lock &>(lock));
}

TEST(lock, lockwait) {
    Mutex lock(0);
    test_timed_lock_timeout(lock, LOCK_EX, LOCK_EX);
    ASSERT_EQ(lock.lock(LOCK_EX, 20), 0);
    EXPECT_EQ(lock.unlock(), 0);
}

TEST(lock, shared) {
    Mutex lock(true);
    test_share_lock_fun(lock);
}

TEST(lock, try_rd) {
    Mutex lock(0);
    test_lock_rd_func(lock);
}

TEST(lock, coroutine_lock) {
    auto *lock = new CoroutineLock(false);
    ASSERT_EQ(lock->lock(), SW_ERROR_CO_OUT_OF_COROUTINE);
    ASSERT_EQ(lock->unlock(), SW_ERROR_CO_OUT_OF_COROUTINE);

    coroutine::run([lock](void *arg) {
        Coroutine::create([lock](void *) {
            ASSERT_EQ(lock->lock(), 0);
            ASSERT_EQ(lock->lock(), 0);
            System::sleep(1);
            ASSERT_EQ(lock->unlock(), 0);
        });

        Coroutine::create([lock](void *) {
            ASSERT_EQ(lock->lock(), 0);
            System::sleep(1);
            ASSERT_EQ(lock->unlock(), 0);
            // unlock 2, no effect
            ASSERT_EQ(lock->unlock(), 0);
        });

        Coroutine::create([lock](void *) { ASSERT_EQ(lock->lock(LOCK_NB), EBUSY); });
    });

    delete lock;
}

#ifndef HAVE_IOURING_FUTEX
TEST(lock, coroutine_lock_cancel) {
    CoroutineLock lock(true);
    coroutine::run([&](void *arg) {
        ASSERT_EQ(lock.lock(), 0);
        Coroutine::create([&](void *) {
            auto co = Coroutine::get_current();
            Coroutine::create([co](void *) {
                // io_uring cancellation waits for completion and requires a coroutine context.
                System::sleep(0.02);
                DEBUG() << "cancel coroutine " << co->get_cid() << "\n";
                co->cancel();
            });
            ASSERT_EQ(lock.lock(), SW_ERROR_CO_CANCELED);
        });
    });
}
#endif

TEST(lock, coroutine_lock_rd) {
    auto *lock = new CoroutineLock(false);
    ASSERT_EQ(lock->lock(LOCK_SH), SW_ERROR_CO_OUT_OF_COROUTINE);

    coroutine::run([lock](void *arg) {
        Coroutine::create([lock](void *) {
            ASSERT_EQ(lock->lock(LOCK_SH), 0);
            ASSERT_EQ(lock->lock(LOCK_SH), 0);
            System::sleep(0.3);
            ASSERT_EQ(lock->unlock(), 0);
        });

        Coroutine::create([lock](void *) {
            ASSERT_EQ(lock->lock(LOCK_SH), 0);
            System::sleep(0.3);
            ASSERT_EQ(lock->unlock(), 0);
        });

        Coroutine::create([lock](void *) { ASSERT_EQ(lock->lock(LOCK_SH | LOCK_NB), EBUSY); });
    });

    delete lock;
}

#ifdef HAVE_RWLOCK
TEST(lock, rwlock_shared) {
    RWLock lock(true);
    test_share_lock_fun(lock);
}

TEST(lock, rwlock) {
    RWLock lock(false);
    test_func(lock);
}

TEST(lock, rwlock_try_rd) {
    RWLock lock(false);
    test_lock_rd_func(lock);
}

TEST(lock, rw_try_wr) {
    RWLock lock(false);
    ASSERT_EQ(lock.lock(), 0);
    std::thread contender([&lock]() {
        const int result = lock.lock(LOCK_NB);
        EXPECT_EQ(result, EBUSY);
        if (result == 0) {
            EXPECT_EQ(lock.unlock(), 0);
        }
    });
    contender.join();
    EXPECT_EQ(lock.unlock(), 0);
}

TEST(lock, rw_timed_reader_waits_for_writer) {
    RWLock lock(false);
    test_timed_lock_timeout(lock, LOCK_EX, LOCK_SH);
}

TEST(lock, rw_timed_writer_waits_for_reader) {
    RWLock lock(false);
    test_timed_lock_timeout(lock, LOCK_SH, LOCK_EX);
}

TEST(lock, rw_timed_writer_waits_for_writer) {
    RWLock lock(false);
    test_timed_lock_timeout(lock, LOCK_EX, LOCK_EX);
}

TEST(lock, rw_timed_readers_can_share) {
    RWLock lock(false);
    ASSERT_EQ(lock.lock(LOCK_SH), 0);
    std::thread reader([&lock]() {
        const int result = lock.lock(LOCK_SH, 20);
        EXPECT_EQ(result, 0);
        if (result == 0) {
            EXPECT_EQ(lock.unlock(), 0);
        }
    });
    reader.join();
    EXPECT_EQ(lock.unlock(), 0);
    ASSERT_EQ(lock.lock(LOCK_EX, 20), 0);
    EXPECT_EQ(lock.unlock(), 0);
}
#endif

#ifdef HAVE_SPINLOCK
TEST(lock, spinlock_shared) {
    SpinLock lock(true);
    test_share_lock_fun(lock);
}

TEST(lock, spinlock) {
    SpinLock lock(false);
    test_func(lock);
}

TEST(lock, spinlock_try_rd) {
    SpinLock lock(false);
    test_lock_rd_func(lock);
}

TEST(lock, spinlock_timeout_and_reuse) {
    SpinLock lock(false);
    test_timed_lock_timeout(lock, LOCK_EX, LOCK_EX);
    ASSERT_EQ(lock.lock(LOCK_EX, 20), 0);
    EXPECT_EQ(lock.unlock(), 0);
}
#endif
