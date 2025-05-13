#include "test_core.h"
#include "swoole_process_pool.h"
#include "swoole_signal.h"

#ifdef HAVE_SIGNALFD
static void sig_usr1(int signo) {}

TEST(os_signal, signalfd) {
    int ret;
    sigset_t curset;

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    sigemptyset(&curset);
    sigprocmask(SIG_BLOCK, NULL, &curset);
    ret = sigismember(&curset, SIGUSR1);
    ASSERT_EQ(ret, 0);

    swoole_signalfd_init();
    swoole_signal_set(SIGUSR1, sig_usr1);

    sigemptyset(&curset);
    sigprocmask(SIG_BLOCK, NULL, &curset);
    ret = sigismember(&curset, SIGUSR1);
    ASSERT_EQ(ret, 1);

    swoole_signal_set(SIGUSR1, NULL);
    swoole_signal_clear();

    sigemptyset(&curset);
    sigprocmask(SIG_BLOCK, NULL, &curset);
    ret = sigismember(&curset, SIGUSR1);
    ASSERT_EQ(ret, 0);

    swoole_event_wait();
}
#endif

TEST(os_signal, block) {
    ASSERT_EQ(swoole::test::spawn_exec_and_wait([]() {
                  sysv_signal(SIGIO, [](int signo) { exit(255); });

                  std::thread t([] {
                      swoole_signal_block_all();
                      pthread_kill(pthread_self(), SIGIO);
                  });
                  t.join();
              }),
              0);
}

TEST(os_signal, unblock) {
    auto status = swoole::test::spawn_exec_and_wait([]() {
        sysv_signal(SIGIO, [](int signo) { exit(255); });

        std::thread t([] {
            swoole_signal_block_all();
            pthread_kill(pthread_self(), SIGIO);
            swoole_signal_unblock_all();
        });
        t.join();
    });

    auto exit_status = swoole::ExitStatus(getpid(), status);

    ASSERT_EQ(exit_status.get_code(), 255);
}

TEST(os_signal, signal_to_str) {
    ASSERT_STREQ(swoole_signal_to_str(SIGTERM), "Terminated: 15");
    ASSERT_STREQ(swoole_signal_to_str(SIGIO), "I/O possible: 29");
    ASSERT_STREQ(swoole_signal_to_str(SIGRTMIN), "Real-time signal 0: 34");
    ASSERT_STREQ(swoole_signal_to_str(99999), "Unknown signal 99999: 99999");
}

TEST(os_signal, set) {
    swoole_signal_set(SIGIO, [](int signo) { exit(255); });
    ASSERT_TRUE(swoole_signal_isset(SIGIO));
    ASSERT_FALSE(swoole_signal_isset(SIGTERM));
    swoole_signal_set(SIGIO, nullptr);
    ASSERT_FALSE(swoole_signal_isset(SIGIO));
}

static int trigger_signal = 0;

TEST(os_signal, dispatch) {
    trigger_signal = 0;
    swoole_signal_set(SIGIO, [](int signo) { trigger_signal = signo; }, true);
    swoole_kill(getpid(), SIGIO);
    ASSERT_EQ(trigger_signal, 0);

    ASSERT_EQ(swoole_signal_get_handler(SIGTERM), nullptr);
    ASSERT_NE(swoole_signal_get_handler(SIGIO), nullptr);

    swoole_signal_dispatch();
    ASSERT_EQ(trigger_signal, SIGIO);

    trigger_signal = 0;

    swoole_signal_dispatch();
    ASSERT_EQ(trigger_signal, 0);

    ASSERT_EQ(swoole_signal_get_listener_num(), 0);

    swoole_signal_clear();
}