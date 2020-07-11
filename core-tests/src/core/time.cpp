#include "tests.h"
#include "swoole_util.h"

TEST(time, get_ms) {
    const int us = 3000;
    long ms1 = swoole::time<std::chrono::milliseconds>();
    usleep(us);
    long ms2 = swoole::time<std::chrono::milliseconds>();
    EXPECT_GE(ms2 - ms1, us / 1000);
}

TEST(time, get_ms_steady) {
    const int us = 3000;
    long ms1 = swoole::time<std::chrono::milliseconds>(true);
    usleep(us);
    long ms2 = swoole::time<std::chrono::milliseconds>(true);
    EXPECT_GE(ms2 - ms1, us / 1000);
}

TEST(time, get_seconds) {
    long sec1 = swoole::time<std::chrono::seconds>();
    time_t sec2 = time(NULL);
    EXPECT_EQ(sec1, sec2);
}
