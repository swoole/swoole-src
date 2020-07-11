#include "test_coroutine.h"

using namespace swoole;
using namespace swoole::test;

TEST(os_wait, waitpid_before_child_exit) {
    test::coroutine::run([](void *arg) {
        pid_t pid = fork();
        ASSERT_NE(pid, -1);

        if (pid == 0) {
            usleep(100000);
            exit(0);
        }

        int status = -1;
        pid_t pid2 = swoole_coroutine_waitpid(pid, &status, 0);
        ASSERT_EQ(status, 0);
        ASSERT_EQ(pid, pid2);
    });
}

TEST(os_wait, waitpid_after_child_exit) {
    test::coroutine::run([](void *arg) {
        pid_t pid = fork();
        ASSERT_NE(pid, -1);

        if (pid == 0) {
            exit(0);
        }

        usleep(100000);
        int status = -1;
        pid_t pid2 = swoole_coroutine_waitpid(pid, &status, 0);
        ASSERT_EQ(status, 0);
        ASSERT_EQ(pid, pid2);
    });
}

TEST(os_wait, wait_before_child_exit) {
    test::coroutine::run([](void *arg) {
        pid_t pid = fork();
        ASSERT_NE(pid, -1);

        if (pid == 0) {
            usleep(100000);
            exit(0);
        }

        int status = -1;
        pid_t pid2 = -1;

        for (;;) {
            pid2 = swoole_coroutine_wait(&status);
            if (pid2 == pid) {
                break;
            }
        }

        ASSERT_EQ(WEXITSTATUS(status), 0);
    });
}

TEST(os_wait, wait_after_child_exit) {
    test::coroutine::run([](void *arg) {
        pid_t pid = fork();
        ASSERT_NE(pid, -1);

        if (pid == 0) {
            exit(0);
        }

        usleep(100000);
        int status = -1;
        pid_t pid2 = -1;

        for (;;) {
            pid2 = swoole_coroutine_wait(&status);
            if (pid2 == pid) {
                break;
            }
        }

        ASSERT_EQ(WEXITSTATUS(status), 0);
    });
}
