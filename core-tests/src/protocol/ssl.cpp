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

#include "test_core.h"
#include "swoole_ssl.h"

using swoole::SSLContext;

std::atomic<int> lock_count(0);
std::atomic<int> unlock_count(0);
std::vector<std::thread> test_threads;

class OpenSSLCallbackTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 重置计数器
        lock_count = 0;
        unlock_count = 0;
    }

    void TearDown() override {
        // 确保所有测试线程已完成
        for (auto& thread : test_threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        test_threads.clear();
    }

    // 模拟 OpenSSL 操作的函数
    static void simulate_openssl_operation(int lock_type) {
        // 锁定
        swoole_ssl_lock_callback(CRYPTO_LOCK, lock_type, __FILE__, __LINE__);
        lock_count++;

        // 模拟一些工作
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        // 解锁
        swoole_ssl_lock_callback(~CRYPTO_LOCK, lock_type, __FILE__, __LINE__);
        unlock_count++;
    }
};

// 测试锁回调函数的基本功能
TEST_F(OpenSSLCallbackTest, LockCallbackBasic) {
    int test_lock_type = 0;  // 使用第一个锁

    swoole_ssl_init();

    // 测试锁定
    swoole_ssl_lock_callback(CRYPTO_LOCK, test_lock_type, __FILE__, __LINE__);

    // 尝试再次锁定（应该会阻塞，所以我们在另一个线程中执行）
    std::atomic<bool> lock_acquired(false);
    std::thread t([test_lock_type, &lock_acquired]() {
        swoole_ssl_lock_callback(CRYPTO_LOCK, test_lock_type, __FILE__, __LINE__);
        lock_acquired = true;
        swoole_ssl_lock_callback(~CRYPTO_LOCK, test_lock_type, __FILE__, __LINE__);
    });

    // 短暂等待，确认锁未被获取
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    EXPECT_FALSE(lock_acquired);

    // 解锁，允许另一个线程获取锁
    swoole_ssl_lock_callback(~CRYPTO_LOCK, test_lock_type, __FILE__, __LINE__);

    // 等待线程完成
    t.join();
    EXPECT_TRUE(lock_acquired);
}

TEST_F(OpenSSLCallbackTest, LockCallbackMultiThreaded) {
    swoole_ssl_init();

    const int num_threads = 10;
    const int operations_per_thread = 100;
    const int num_locks = CRYPTO_num_locks();

    // 创建多个线程，每个线程执行多次锁定/解锁操作
    for (int i = 0; i < num_threads; i++) {
        test_threads.emplace_back([operations_per_thread, num_locks]() {
            for (int j = 0; j < operations_per_thread; j++) {
                // 随机选择一个锁
                int lock_type = rand() % num_locks;
                simulate_openssl_operation(lock_type);
            }
        });
    }

    // 等待所有线程完成
    for (auto& thread : test_threads) {
        thread.join();
    }
    test_threads.clear();

    // 验证锁定和解锁的次数相等
    EXPECT_EQ(lock_count, num_threads * operations_per_thread);
    EXPECT_EQ(unlock_count, num_threads * operations_per_thread);
}

TEST_F(OpenSSLCallbackTest, ErrorCallback) {
    ERR_put_error(ERR_LIB_BIO, BIO_F_BIO_SOCK_INIT, BIO_R_UNABLE_TO_BIND_SOCKET, __FILE__, __LINE__);

    const char* error_msg = swoole_ssl_get_error();

    EXPECT_NE(error_msg, nullptr);
    EXPECT_GT(strlen(error_msg), 0);

    EXPECT_TRUE(strstr(error_msg, "BIO") != nullptr ||
                strstr(error_msg, "bind") != nullptr ||
                strstr(error_msg, "socket") != nullptr);
}

