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
  | @author   Tianfeng Han  <mikan.tenny@gmail.com>                      |
  +----------------------------------------------------------------------+
*/

#include "test_core.h"
#include "swoole_lock.h"
#include "swoole_util.h"

#include <thread>

using swLock = swoole::Lock;

using swoole::RWLock;
using swoole::SpinLock;
using swoole::Mutex;

static void test_func(swLock &lock) {
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

TEST(lock, mutex) {
    Mutex lock(0);
    test_func( reinterpret_cast<swLock &>(lock));
}

TEST(lock, lockwait) {
    Mutex lock(0);

    lock.lock();

    std::thread t1([&lock]() {
        long ms1 = swoole::time<std::chrono::milliseconds>();
        const int TIMEOUT_1 = 2;
        ASSERT_EQ(lock.lock_wait(TIMEOUT_1), ETIMEDOUT);
        long ms2 = swoole::time<std::chrono::milliseconds>();

        ASSERT_GE(ms2 - ms1, TIMEOUT_1);

        const int TIMEOUT_2 = 10;
        ASSERT_EQ(lock.lock_wait(TIMEOUT_2), 0);
        long ms3 = swoole::time<std::chrono::milliseconds>();

        ASSERT_LE(ms3 - ms2, TIMEOUT_2);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    lock.unlock();

    t1.join();
}

TEST(lock, shared) {
    Mutex lock(Mutex::PROCESS_SHARED);

    lock.lock();

    const int sleep_us = 10000;

    int magic_num = swoole_rand(100000, 9999999);
    int *_num = (int *) sw_mem_pool()->alloc(sizeof(int));
    *_num = 0;

    pid_t pid = fork() ;

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
        if (_pid != pid ) {
            swWarn("error pid=%d", _pid);
        }
        ASSERT_EQ(*_num, magic_num);
    }
}

#ifdef HAVE_RWLOCK
TEST(lock, rwlock) {
    RWLock lock(false);
    test_func(lock);
}
#endif

#ifdef HAVE_SPINLOCK
TEST(lock, spinlock) {
    SpinLock lock(false);
    test_func(lock);
}
#endif
