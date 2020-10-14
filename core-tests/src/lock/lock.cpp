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
#include "swoole_util.h"
#include <thread>

static void test_func(swLock &lock) {
    int count = 0;
    const int N = 100000;

    auto fn = [&]() {
        for (int i = 0; i < N; i++) {
            ASSERT_EQ(lock.lock(&lock), 0);
            count++;
            ASSERT_EQ(lock.unlock(&lock), 0);
        }
    };

    std::thread t1(fn);
    std::thread t2(fn);

    t1.join();
    t2.join();

    ASSERT_EQ(count, N * 2);
}

TEST(lock, mutex) {
    swLock lock;
    swMutex_create(&lock, 0);
    test_func(lock);
}

TEST(lock, lockwait) {
    swLock lock;
    swMutex_create(&lock, 0);

    lock.lock(&lock);

    std::thread t1([&lock]() {
        long ms1 = swoole::time<std::chrono::milliseconds>();
        const int TIMEOUT_1 = 2;
        ASSERT_EQ(swMutex_lockwait(&lock, TIMEOUT_1), ETIMEDOUT);
        long ms2 = swoole::time<std::chrono::milliseconds>();

        ASSERT_GE(ms2 - ms1, TIMEOUT_1);

        const int TIMEOUT_2 = 10;
        ASSERT_EQ(swMutex_lockwait(&lock, TIMEOUT_2), 0);
        long ms3 = swoole::time<std::chrono::milliseconds>();

        ASSERT_LE(ms3 - ms2, TIMEOUT_2);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    lock.unlock(&lock);

    t1.join();
}

TEST(lock, rwlock) {
    swLock lock;
    swRWLock_create(&lock, 0);
    test_func(lock);
}

#ifdef HAVE_SPINLOCK
TEST(lock, spinlock) {
    swLock lock;
    swSpinLock_create(&lock, 0);
    test_func(lock);
}
#endif
