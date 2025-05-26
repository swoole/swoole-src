#include "test_coroutine.h"

using namespace swoole;
using namespace swoole::test;
using swoole::coroutine::System;

static pid_t fork_child() {
    pid_t pid = fork();
    EXPECT_NE(pid, -1);

    if (pid == 0) {
        usleep(100000);
        exit(0);
    }
    return pid;
}

static pid_t fork_child2() {
    pid_t pid = fork();
    EXPECT_NE(pid, -1);

    if (pid == 0) {
        exit(0);
    }

    usleep(100000);
    return pid;
}

TEST(os_wait, waitpid_before_child_exit) {
    test::coroutine::run([](void *arg) {
        auto pid = fork_child();
        int status = -1;
        pid_t pid2 = swoole_coroutine_waitpid(pid, &status, 0);
        ASSERT_EQ(status, 0);
        ASSERT_EQ(pid, pid2);
    });
}

TEST(os_wait, waitpid_after_child_exit) {
    test::coroutine::run([](void *arg) {
        pid_t pid = fork_child2();
        int status = -1;
        pid_t pid2 = swoole_coroutine_waitpid(pid, &status, 0);
        ASSERT_EQ(status, 0);
        ASSERT_EQ(pid, pid2);
    });
}

TEST(os_wait, wait_before_child_exit) {
    test::coroutine::run([](void *arg) {
        pid_t pid = fork_child();
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
        pid_t pid = fork_child2();
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

TEST(os_wait, waitpid_safe) {
    test::coroutine::run([](void *arg) {
        pid_t pid = fork_child();
        int status = -1;

        pid_t pid2 = System::waitpid_safe(pid, &status, 0);
        ASSERT_EQ(pid2, pid);
        ASSERT_EQ(WEXITSTATUS(status), 0);
    });
}
