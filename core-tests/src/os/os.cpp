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

#include "swoole_file.h"
#include "swoole_thread.h"

using namespace swoole;

TEST(os, daemon) {
    auto sid = getsid(getpid());
    int status;
    swoole_waitpid(test::spawn_exec([sid]() {
                       ASSERT_EQ(sid, getsid(getpid()));
                       ASSERT_TRUE(isatty(STDIN_FILENO));

                       ASSERT_EQ(swoole_daemon(0, 0), 0);
                       ASSERT_NE(sid, getsid(getpid()));

                       ASSERT_FALSE(isatty(STDIN_FILENO));
                   }),
                   &status,
                   0);
}

TEST(os, cpu_affinity) {
    cpu_set_t ori_affinity, affinity;
    ASSERT_EQ(swoole_get_cpu_affinity(&affinity), 0);
    ori_affinity = affinity;

    CPU_ZERO(&affinity);
    CPU_SET(1, &affinity);

    ASSERT_EQ(swoole_set_cpu_affinity(&affinity), 0);
    ASSERT_EQ(swoole_get_cpu_affinity(&affinity), 0);

    auto cpu_n = SW_CPU_NUM;
    SW_LOOP_N(cpu_n) {
        if (i == 1) {
            ASSERT_TRUE(CPU_ISSET(i, &affinity));
        } else {
            ASSERT_FALSE(CPU_ISSET(i, &affinity));
        }
    }

    ASSERT_EQ(swoole_set_cpu_affinity(&ori_affinity), 0);
}

TEST(os, thread_name) {
    std::thread t([]() {
        char new_name[512];
        auto thread_name = "sw-core-tests";
        ASSERT_TRUE(swoole_thread_set_name(thread_name));
        ASSERT_TRUE(swoole_thread_get_name(new_name, sizeof(new_name)));

        ASSERT_STREQ(thread_name, new_name);

        ASSERT_FALSE(swoole_thread_set_name("swoole-core-tests-max-size-is-16"));
        ASSERT_EQ(swoole_get_last_error(), ERANGE);
    });
    t.join();
}

TEST(os, thread_id) {
    auto tid = swoole_thread_id_to_str(std::this_thread::get_id());
    DEBUG() << "current thread id: " << tid << "\n";
    ASSERT_FALSE(tid.empty());
}

TEST(os, set_isolation) {
    swoole_set_isolation("not-exists-group", "not-exists-user", "/tmp/not-exists-dir");
}
