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

#include <grp.h>
#include <pwd.h>

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

TEST(os, validate_isolation) {
    EXPECT_TRUE(swoole_validate_isolation("", "", "").empty());
    EXPECT_TRUE(swoole_validate_isolation("", "", "/tmp").empty());

    const std::string missing = "swoole-isolation-missing-" + std::to_string(getpid());
    EXPECT_NE(swoole_validate_isolation(missing, "", "").find(missing), std::string::npos);
    EXPECT_NE(swoole_validate_isolation("", missing, "").find(missing), std::string::npos);
    EXPECT_EQ(swoole_validate_isolation("", "", std::string("/tmp\0extra", 10)), "chroot must not contain null bytes");

    const auto file = make_tmpfile();
    ASSERT_TRUE(file.ready());
    ON_SCOPE_EXIT {
        unlink(file.get_path().c_str());
    };
    EXPECT_EQ(swoole_validate_isolation("", "", file.get_path()),
              "chroot '" + file.get_path() + "' is not a directory");
}

TEST(os, set_isolation) {
    EXPECT_TRUE(swoole_set_isolation("", "", ""));
    const std::string missing = "swoole-isolation-missing-" + std::to_string(getpid());
    EXPECT_FALSE(swoole_set_isolation(missing, "", ""));
    EXPECT_FALSE(swoole_set_isolation("", missing, ""));

    const auto file = make_tmpfile();
    ASSERT_TRUE(file.ready());
    ON_SCOPE_EXIT {
        unlink(file.get_path().c_str());
    };
    EXPECT_FALSE(swoole_set_isolation("", "", file.get_path()));
}

TEST(os, set_isolation_chroot_and_drop_identity) {
    if (!swoole_is_root_user()) {
        GTEST_SKIP() << "requires privileges to set credentials and chroot";
    }
    const auto *account = getpwnam("nobody");
    if (!account || account->pw_uid == 0) {
        GTEST_SKIP() << "requires an unprivileged nobody account";
    }
    const std::string user = account->pw_name;
    const uid_t uid = account->pw_uid;
    const gid_t gid = account->pw_gid;
    const auto *group = getgrgid(gid);
    ASSERT_NE(group, nullptr);
    const std::string group_name = group->gr_name;
    char root[] = "/tmp/swoole-isolation.XXXXXX";
    ASSERT_NE(mkdtemp(root), nullptr);
    const std::string marker = std::string(root) + "/worker-root";
    ON_SCOPE_EXIT {
        unlink(marker.c_str());
        rmdir(root);
    };
    ASSERT_EQ(chmod(root, 0755), 0);
    const File file(marker, O_CREAT | O_WRONLY, 0644);
    ASSERT_TRUE(file.ready());

    const pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        const gid_t inherited = gid == 0 ? 1 : 0;
        gid_t supplementary;
        if (setgroups(1, &inherited) < 0 || !swoole_set_isolation(group_name, "", "") || geteuid() != 0 ||
            getgid() != gid || getgroups(1, &supplementary) != 1 || supplementary != gid) {
            _exit(EXIT_FAILURE);
        }
        const bool isolated = swoole_set_isolation("", user, root);
        const bool expected_identity = getuid() == uid && geteuid() == uid && getgid() == gid && getegid() == gid;
        _exit(isolated && expected_identity && access("worker-root", R_OK) == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    int status;
    ASSERT_EQ(swoole_waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);
}
