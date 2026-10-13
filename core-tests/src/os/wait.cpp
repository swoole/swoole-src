#include "test_coroutine.h"
#include "swoole_process_pool.h"

using namespace swoole;
using namespace swoole::test;
using swoole::coroutine::System;

#ifndef _WIN32
static volatile sig_atomic_t wait_signal_received = 0;

TEST(os_wait, signal_before_wait) {
    const auto status = test::spawn_exec_and_wait([] {
        SwooleG.signal_alarm = false;
        SwooleG.signal_dispatch = false;
        sigset_t mask;
        sigemptyset(&mask);
        sigprocmask(SIG_SETMASK, &mask, nullptr);
        int pipe_fds[2];
        if (pipe(pipe_fds) < 0) {
            _exit(1);
        }
        const auto pid = fork();
        if (pid < 0) {
            _exit(1);
        }
        if (pid == 0) {
            close(pipe_fds[1]);
            char byte;
            read(pipe_fds[0], &byte, 1);
            _exit(0);
        }
        close(pipe_fds[0]);

        // A broken wait must fail promptly; closing the pipe on exit also releases the child.
        signal(SIGALRM, [](int) { _exit(2); });
        alarm(2);
        signal(SIGCHLD, SIG_DFL);
        signal(SIGUSR1, [](int) { wait_signal_received = 1; });
        wait_signal_received = 0;
        const auto exit_status = wait_process([] {
            // Inject the request after deciding to wait, before entering the blocking syscall.
            const bool should_wait = !wait_signal_received;
            kill(getpid(), SIGUSR1);
            return should_wait;
        });
        const bool woke_for_signal = wait_signal_received && exit_status.get_pid() == 0;
        // Also cover waking for a child exit with the default SIGCHLD disposition.
        const auto child_status = wait_process([&] {
            close(pipe_fds[1]);
            return true;
        });
        alarm(0);
        _exit(woke_for_signal && child_status.get_pid() == pid && child_status.get_status() == 0 ? 0 : 1);
    });
    ASSERT_EQ(status, 0);
}
#endif

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
