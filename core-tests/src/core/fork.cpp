#include "test_core.h"
#include "swoole_api.h"
#include "swoole_memory.h"
#include "swoole_process_pool.h"
#include "swoole_signal.h"
#include "swoole_timer.h"

#ifndef _WIN32
TEST(fork_exec, child_runtime_cleanup) {
    // Isolate hook registration and the temporary reactor from the test runner.
    auto status = swoole::test::spawn_exec_and_wait([] {
        bool after_fork = false;
        swoole::hook_add(SwooleG.hooks, SW_GLOBAL_HOOK_AFTER_FORK, [&after_fork](void *) { after_fork = true; }, 0);

        auto *pool = sw_mem_pool();
        auto *shared = static_cast<sw_atomic_t *>(pool->alloc(sizeof(sw_atomic_t)));
        *shared = 0;
        if (swoole_event_init(SW_EVENTLOOP_WAIT_EXIT) < 0) {
            exit(1);
        }
        auto *reactor = sw_reactor();
        auto *node = swoole_timer_add(10000L, false, [](swoole::Timer *, swoole::TimerNode *) {});
        auto *timer = sw_timer();
        if (!node) {
            exit(2);
        }
        swoole_signal_set(SIGUSR1, [](int) {});

        pid_t pid = swoole_fork_exec([&] {
            sigset_t mask;
            sigprocmask(SIG_BLOCK, nullptr, &mask);
            if (!after_fork || sw_mem_pool() == pool || sw_timer() || sw_reactor() ||
                swoole_signal_get_handler(SIGUSR1) || sigismember(&mask, SIGUSR1)) {
                exit(3);
            }
            auto *allocation = static_cast<sw_atomic_t *>(sw_mem_pool()->alloc(sizeof(sw_atomic_t)));
            *allocation = 7;
            *shared = 42;
        });
        if (pid < 0) {
            exit(4);
        }
        int child_status;
        if (swoole_waitpid(pid, &child_status, 0) != pid || !WIFEXITED(child_status) ||
            WEXITSTATUS(child_status) != 0) {
            exit(5);
        }
        const bool parent_intact = !after_fork && sw_mem_pool() == pool && sw_reactor() == reactor &&
                                   sw_timer() == timer && swoole_signal_get_handler(SIGUSR1) && *shared == 42;
        swoole_timer_free();
        swoole_event_free();
        swoole_signal_clear();
        exit(parent_intact ? 0 : 6);
    });
    ASSERT_EQ(status, 0);
}
#endif
