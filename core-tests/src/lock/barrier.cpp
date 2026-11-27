#include "swoole_lock.h"

#include <gtest/gtest.h>

#include <chrono>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <sys/mman.h>
#include <sys/wait.h>

using swoole::Barrier;

static void barrier_watchdog() {
    // Keep a broken generation from hanging the suite or leaving a stuck child process behind.
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    pthread_sigmask(SIG_UNBLOCK, &mask, nullptr);
    signal(SIGALRM, [](int) { _exit(124); });
    alarm(10);
}

TEST(barrier, single_participant_and_reinitialization) {
    ASSERT_EXIT(
        {
            barrier_watchdog();
            Barrier barrier;
            for (int reuse = 0; reuse < 2; ++reuse) {
                barrier.init(false, 1);
                for (int round = 0; round < 64; ++round) {
                    barrier.wait();
                }
                barrier.destroy();
            }
            _exit(0);
        },
        ::testing::ExitedWithCode(0),
        "");
}

TEST(barrier, repeated_thread_generations_publish_all_arrivals) {
    ASSERT_EXIT(
        {
            barrier_watchdog();
            const int participants = 4;
            Barrier barrier;
            barrier.init(false, participants);
            std::vector<int> values(participants, 0);
            std::vector<std::thread> threads;
            for (int id = 0; id < participants; ++id) {
                threads.emplace_back([&, id] {
                    for (int round = 1; round <= 64; ++round) {
                        // Rotate the late arrival so faster participants also enter the next generation first.
                        if (round % participants == id) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(1));
                        }
                        values[id] = round;
                        barrier.wait();
                        for (int value : values) {
                            EXPECT_EQ(value, round);
                        }
                        // No participant may overwrite its slot while another still reads this generation.
                        barrier.wait();
                    }
                });
            }
            for (auto &thread : threads) {
                thread.join();
            }
            barrier.destroy();
            _exit(::testing::Test::HasFailure() ? 1 : 0);
        },
        ::testing::ExitedWithCode(0),
        "");
}

TEST(barrier, repeated_process_shared_generations) {
    ASSERT_EXIT(
        {
            barrier_watchdog();
            struct State {
                Barrier barrier;
                int values[2];
            };
            void *memory = mmap(nullptr, sizeof(State), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
            if (memory == MAP_FAILED) {
                _exit(1);
            }
            auto *state = new (memory) State{};
            state->barrier.init(true, 2);
            const pid_t child = fork();
            if (child < 0) {
                _exit(2);
            }
            // alarm() is not inherited across fork: bound both participants independently.
            barrier_watchdog();
            const int id = child == 0 ? 1 : 0;
            for (int round = 1; round <= 32; ++round) {
                if (round % 2 == id) {
                    usleep(1000);
                }
                state->values[id] = round;
                state->barrier.wait();
                if (state->values[1 - id] != round) {
                    _exit(3);
                }
                state->barrier.wait();
            }
            if (child == 0) {
                _exit(0);
            }
            int status;
            if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                _exit(4);
            }
            state->barrier.destroy();
            state->~State();
            munmap(memory, sizeof(State));
            _exit(0);
        },
        ::testing::ExitedWithCode(0),
        "");
}
#endif
