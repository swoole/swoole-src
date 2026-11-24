#include "test_core.h"
#include "swoole_process_pool.h"
#include "swoole_signal.h"
#include "swoole_reactor.h"

#ifndef _WIN32
namespace {
volatile sig_atomic_t received_handler;
volatile sig_atomic_t received_signals;

void original_handler(int) {
    received_handler = 1;
}

void temporary_handler(int) {
    received_handler = 2;
}

void child_handler(int) {
    received_handler = 3;
}

void siginfo_handler(int, siginfo_t *, void *) {
    received_handler = 4;
}

int run_signal_guard_test(const std::function<void()> &fn) {
    return swoole::test::spawn_exec_and_wait([&] {
        // Isolate dispositions and masks from the other signal tests, and bound a lost signal listener.
        swoole_event_free();
        swoole_signal_clear();
        SwooleG.enable_signalfd = false;
        SwooleG.enable_kqueue = false;
        SwooleG.signal_dispatch = false;
        sigset_t empty;
        sigemptyset(&empty);
        if (pthread_sigmask(SIG_SETMASK, &empty, nullptr) != 0) {
            _exit(1);
        }
        signal(SIGALRM, [](int) { _exit(124); });
        alarm(5);
        fn();
        // ASSERT_* returns from fn, so propagate failures to the parent instead of exiting successfully.
        _exit(::testing::Test::HasFailure() ? 1 : 0);
    });
}

void expect_same_mask(const sigset_t &expected, const sigset_t &actual) {
    for (int signo = 1; signo < NSIG; signo++) {
        EXPECT_EQ(sigismember(&actual, signo), sigismember(&expected, signo)) << "signal=" << signo;
    }
}

void expect_same_action(const struct sigaction &expected, const struct sigaction &actual) {
    EXPECT_EQ(actual.sa_flags, expected.sa_flags);
    if (expected.sa_flags & SA_SIGINFO) {
        EXPECT_EQ(actual.sa_sigaction, expected.sa_sigaction);
    } else {
        EXPECT_EQ(actual.sa_handler, expected.sa_handler);
    }
    expect_same_mask(expected.sa_mask, actual.sa_mask);
}
}  // namespace

TEST(os_signal, guard_restores_sigaction_and_mask) {
    for (bool blocked : {false, true}) {
        ASSERT_EQ(run_signal_guard_test([blocked] {
                      struct sigaction action{}, expected_action{}, actual_action{};
                      action.sa_sigaction = siginfo_handler;
                      action.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;
                      sigemptyset(&action.sa_mask);
                      sigaddset(&action.sa_mask, SIGUSR2);
                      ASSERT_EQ(sigaction(SIGUSR1, &action, nullptr), 0);
                      ASSERT_EQ(sigaction(SIGUSR1, nullptr, &expected_action), 0);

                      sigset_t expected_mask, actual_mask;
                      sigemptyset(&expected_mask);
                      sigaddset(&expected_mask, SIGWINCH);  // An unrelated blocked signal must also stay blocked.
                      if (blocked) {
                          sigaddset(&expected_mask, SIGUSR1);
                      }
                      ASSERT_EQ(pthread_sigmask(SIG_SETMASK, &expected_mask, nullptr), 0);
                      ASSERT_EQ(pthread_sigmask(SIG_BLOCK, nullptr, &expected_mask), 0);
                      {
                          swoole::SignalGuard guard({SIGUSR1}, temporary_handler);
                          EXPECT_EQ(swoole_signal_get_handler(SIGUSR1), temporary_handler);
                          ASSERT_EQ(pthread_sigmask(SIG_BLOCK, nullptr, &actual_mask), 0);
                          expect_same_mask(expected_mask, actual_mask);
                          if (!blocked) {
                              received_handler = 0;
                              ASSERT_EQ(raise(SIGUSR1), 0);
                              EXPECT_EQ(received_handler, 2);
                          }
                      }
                      ASSERT_EQ(sigaction(SIGUSR1, nullptr, &actual_action), 0);
                      expect_same_action(expected_action, actual_action);
                      ASSERT_EQ(pthread_sigmask(SIG_BLOCK, nullptr, &actual_mask), 0);
                      expect_same_mask(expected_mask, actual_mask);
                      EXPECT_FALSE(swoole_signal_isset(SIGUSR1));
                      EXPECT_EQ(swoole_signal_get_handler(SIGUSR1), nullptr);

                      sigemptyset(&actual_mask);
                      sigaddset(&actual_mask, SIGUSR1);
                      ASSERT_EQ(pthread_sigmask(SIG_UNBLOCK, &actual_mask, nullptr), 0);
                      received_handler = 0;
                      ASSERT_EQ(raise(SIGUSR1), 0);
                      EXPECT_EQ(received_handler, 4);
                  }),
                  0)
            << "blocked=" << blocked;
    }
}

TEST(os_signal, guard_restores_callback_and_origin_action) {
    ASSERT_EQ(run_signal_guard_test([] {
                  struct sigaction action{}, expected_origin{}, expected_action{}, actual{};
                  action.sa_sigaction = siginfo_handler;
                  action.sa_flags = SA_SIGINFO | SA_RESTART;
                  sigemptyset(&action.sa_mask);
                  sigaddset(&action.sa_mask, SIGUSR2);
                  ASSERT_EQ(sigaction(SIGUSR1, &action, nullptr), 0);
                  ASSERT_EQ(sigaction(SIGUSR1, nullptr, &expected_origin), 0);
                  swoole_signal_set(SIGUSR1, original_handler);
                  ASSERT_EQ(sigaction(SIGUSR1, nullptr, &expected_action), 0);
                  {
                      swoole::SignalGuard outer({SIGUSR1}, temporary_handler);
                      {
                          swoole::SignalGuard inner({SIGUSR1}, child_handler);
                          received_handler = 0;
                          ASSERT_EQ(raise(SIGUSR1), 0);
                          EXPECT_EQ(received_handler, 3);
                      }
                      EXPECT_EQ(swoole_signal_get_handler(SIGUSR1), temporary_handler);
                      received_handler = 0;
                      ASSERT_EQ(raise(SIGUSR1), 0);
                      EXPECT_EQ(received_handler, 2);
                  }
                  EXPECT_EQ(swoole_signal_get_handler(SIGUSR1), original_handler);
                  EXPECT_TRUE(swoole_signal_isset(SIGUSR1));
                  ASSERT_EQ(sigaction(SIGUSR1, nullptr, &actual), 0);
                  expect_same_action(expected_action, actual);
                  received_handler = 0;
                  ASSERT_EQ(raise(SIGUSR1), 0);
                  EXPECT_EQ(received_handler, 1);

                  // Unregistering after restoration must still find the action saved before Swoole took over.
                  swoole_signal_set(SIGUSR1, nullptr);
                  ASSERT_EQ(sigaction(SIGUSR1, nullptr, &actual), 0);
                  expect_same_action(expected_origin, actual);
                  received_handler = 0;
                  ASSERT_EQ(raise(SIGUSR1), 0);
                  EXPECT_EQ(received_handler, 4);
              }),
              0);
}

TEST(os_signal, guard_preserves_fork_child_state) {
    ASSERT_EQ(run_signal_guard_test([] {
                  swoole_signal_set(SIGUSR1, original_handler);
                  pid_t child;
                  {
                      swoole::SignalGuard guard({SIGUSR1}, temporary_handler);
                      child = fork();
                      ASSERT_GE(child, 0);
                      if (child == 0) {
                          swoole_signal_clear();
                          swoole_signal_set(SIGUSR1, child_handler);
                          sigset_t mask;
                          sigemptyset(&mask);
                          sigaddset(&mask, SIGUSR1);
                          if (pthread_sigmask(SIG_BLOCK, &mask, nullptr) != 0) {
                              _exit(1);
                          }
                      }
                  }
                  if (child == 0) {
                      sigset_t mask;
                      if (swoole_signal_get_handler(SIGUSR1) != child_handler ||
                          pthread_sigmask(SIG_BLOCK, nullptr, &mask) != 0 || sigismember(&mask, SIGUSR1) != 1) {
                          _exit(2);
                      }
                      sigemptyset(&mask);
                      sigaddset(&mask, SIGUSR1);
                      pthread_sigmask(SIG_UNBLOCK, &mask, nullptr);
                      received_handler = 0;
                      raise(SIGUSR1);
                      _exit(received_handler == 3 ? 0 : 3);
                  }
                  int status;
                  ASSERT_EQ(swoole_waitpid(child, &status, 0), child);
                  ASSERT_EQ(status, 0);
                  EXPECT_EQ(swoole_signal_get_handler(SIGUSR1), original_handler);
                  received_handler = 0;
                  ASSERT_EQ(raise(SIGUSR1), 0);
                  EXPECT_EQ(received_handler, 1);
              }),
              0);
}

#ifdef HAVE_SIGNALFD
namespace {
void signalfd_handler(int signo) {
    received_signals |= signo == SIGUSR1 ? 1 : 2;
    if (received_signals == 3) {
        sw_reactor()->running = false;
    }
}

void check_signalfd_restoration(bool clear_fd) {
    SwooleG.enable_signalfd = true;
    ASSERT_EQ(swoole_event_init(SW_EVENTLOOP_WAIT_EXIT), SW_OK);
    swoole_signal_set(SIGUSR1, signalfd_handler);
    swoole_signal_set(SIGUSR2, signalfd_handler);
    swoole_event_free();
    {
        swoole::SignalGuard guard({SIGUSR1, SIGUSR2}, temporary_handler);
        sigset_t mask;
        ASSERT_EQ(pthread_sigmask(SIG_BLOCK, nullptr, &mask), 0);
        EXPECT_EQ(sigismember(&mask, SIGUSR1), 0);
        EXPECT_EQ(sigismember(&mask, SIGUSR2), 0);
        for (int signo : {SIGUSR1, SIGUSR2}) {
            received_handler = 0;
            ASSERT_EQ(raise(signo), 0);
            EXPECT_EQ(received_handler, 2);
        }
        if (clear_fd) {
            swoole_signal_clear();
        }
    }
    EXPECT_EQ(swoole_signal_get_handler(SIGUSR1), signalfd_handler);
    EXPECT_EQ(swoole_signal_get_handler(SIGUSR2), signalfd_handler);
    sigset_t mask;
    ASSERT_EQ(pthread_sigmask(SIG_BLOCK, nullptr, &mask), 0);
    EXPECT_EQ(sigismember(&mask, SIGUSR1), 1);
    EXPECT_EQ(sigismember(&mask, SIGUSR2), 1);
    ASSERT_NE(fcntl(SwooleG.signal_fd, F_GETFD), -1);

    received_signals = 0;
    SwooleG.wait_signal = true;
    SwooleG.signal_listener_num = 2;
    ASSERT_EQ(swoole_event_init(SW_EVENTLOOP_WAIT_EXIT), SW_OK);
    swoole_event_defer(
        [](void *) {
            raise(SIGUSR1);
            raise(SIGUSR2);
        },
        nullptr);
    ASSERT_EQ(swoole_event_wait(), SW_OK);
    EXPECT_EQ(received_signals, 3);
}
}  // namespace

TEST(os_signal, guard_restores_signalfd_registration) {
    ASSERT_EQ(run_signal_guard_test([] { check_signalfd_restoration(false); }), 0);
}

TEST(os_signal, guard_recreates_cleared_signalfd) {
    ASSERT_EQ(run_signal_guard_test([] { check_signalfd_restoration(true); }), 0);
}

TEST(os_signal, init_reactor_without_global_reactor) {
    ASSERT_EQ(run_signal_guard_test([] {
                  SwooleG.enable_signalfd = true;
                  ASSERT_EQ(swoole_event_init(SW_EVENTLOOP_WAIT_EXIT), SW_OK);
                  swoole_signal_set(SIGUSR1, signalfd_handler);
                  swoole_event_free();
                  ASSERT_EQ(sw_reactor(), nullptr);
                  {
                      // Signal initialization and cleanup must use the supplied reactor before it is published.
                      swoole::Reactor reactor(SW_REACTOR_MAXEVENTS);
                      ASSERT_TRUE(reactor.ready());
                      swoole_signal_init_reactor(&reactor);
                      EXPECT_EQ(sw_reactor(), nullptr);
                      EXPECT_TRUE(reactor.isset_handler(SW_FD_SIGNAL, SW_EVENT_READ));
                      EXPECT_TRUE(reactor.isset_exit_condition(swoole::Reactor::EXIT_CONDITION_SIGNAL_LISTENER));
                      EXPECT_TRUE(reactor.isset_exit_condition(swoole::Reactor::EXIT_CONDITION_SIGNALFD));
                  }
                  EXPECT_EQ(sw_reactor(), nullptr);
                  EXPECT_NE(fcntl(SwooleG.signal_fd, F_GETFD), -1);
              }),
              0);
}
#endif
#endif
