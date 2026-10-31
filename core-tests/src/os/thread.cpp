#include "test_core.h"
#include "swoole_signal.h"
#include "swoole_thread.h"

#include <stdexcept>

#ifndef _WIN32
TEST(thread, start_with_signals_blocked) {
    for (bool already_blocked : {false, true}) {
        auto status = swoole::test::spawn_exec_and_wait([already_blocked]() {
            sigset_t expected, actual, inherited;
            sigemptyset(&expected);
            sigaddset(&expected, SIGUSR1);
            if (pthread_sigmask(SIG_SETMASK, &expected, nullptr) != 0) {
                _exit(1);
            }
            if (already_blocked) {
                swoole_signal_block_all();
            }
            pthread_sigmask(SIG_BLOCK, nullptr, &expected);

            swoole::Thread thread;
            thread.start([&inherited]() {
                // Check before any child-thread initialization can block signals.
                if (pthread_sigmask(SIG_BLOCK, nullptr, &inherited) != 0) {
                    _exit(2);
                }
            });
            thread.join();

            for (int signo : {SIGCHLD, SIGUSR1, SIGTERM}) {
                if (sigismember(&inherited, signo) != 1) {
                    _exit(3);
                }
            }
            if (SwooleTG.signal_blocking_all != already_blocked || pthread_sigmask(SIG_BLOCK, nullptr, &actual) != 0) {
                _exit(4);
            }
            for (int signo = 1; signo < NSIG; signo++) {
                if (sigismember(&expected, signo) != sigismember(&actual, signo)) {
                    _exit(5);
                }
            }
        });
        ASSERT_EQ(status, 0) << "already_blocked=" << already_blocked;
    }
}

TEST(thread, start_failure_restores_signal_mask) {
    auto status = swoole::test::spawn_exec_and_wait([]() {
        struct Callback {
            int *copies;
            explicit Callback(int *count) : copies(count) {}
            Callback(const Callback &other) : copies(other.copies) {
                // The first copy is the start() argument; the second is stored by std::thread.
                if (++*copies == 2) {
                    throw std::runtime_error("callback copy failed");
                }
            }
            void operator()() const {}
        };

        sigset_t expected, actual;
        sigemptyset(&expected);
        sigaddset(&expected, SIGUSR1);
        if (pthread_sigmask(SIG_SETMASK, &expected, nullptr) != 0) {
            _exit(1);
        }
        int copies = 0;
        bool failed = false;
        Callback callback(&copies);
        swoole::Thread thread;
        try {
            thread.start(callback);
        } catch (const std::runtime_error &) {
            failed = true;
        }
        if (thread.joinable()) {
            thread.join();
            _exit(2);
        }
        if (!failed || copies != 2 || SwooleTG.signal_blocking_all ||
            pthread_sigmask(SIG_BLOCK, nullptr, &actual) != 0) {
            _exit(3);
        }
        for (int signo = 1; signo < NSIG; signo++) {
            if (sigismember(&expected, signo) != sigismember(&actual, signo)) {
                _exit(4);
            }
        }
    });
    ASSERT_EQ(status, 0);
}
#endif
