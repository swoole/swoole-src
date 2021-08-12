#include "test_core.h"
#include "swoole_signal.h"

#ifdef HAVE_SIGNALFD
static void sig_usr1(int signo) {}

TEST(os_signal, swSignalfd_set) {
    int ret;
    sigset_t curset;

    SwooleG.use_signalfd = 1;

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    sigemptyset(&curset);
    sigprocmask(SIG_BLOCK, NULL, &curset);
    ret = sigismember(&curset, SIGUSR1);
    ASSERT_EQ(ret, 0);

    swoole_signalfd_init();
    swoole_signal_set(SIGUSR1, sig_usr1);
    swoole_signalfd_setup(SwooleTG.reactor);

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
