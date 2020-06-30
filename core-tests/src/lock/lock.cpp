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

#include "tests.h"
#include <thread>

static void test_func(swLock &lock)
{
    int count = 0;
    const int N = 100000;

    auto fn = [&]()
    {
        for (int i=0; i<N; i++)
        {
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

TEST(lock, atomic)
{
    swLock lock;
    swAtomicLock_create(&lock);
    test_func(lock);
}

TEST(lock, mutex)
{
    swLock lock;
    swMutex_create(&lock, 0);
    test_func(lock);
}

TEST(lock, rwlock)
{
    swLock lock;
    swRWLock_create(&lock, 0);
    test_func(lock);
}

#ifdef HAVE_SPINLOCK
TEST(lock, spinlock)
{
    swLock lock;
    swSpinLock_create(&lock, 0);
    test_func(lock);
}
#endif
