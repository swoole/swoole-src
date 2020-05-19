#include "tests.h"

TEST(time, get_ms)
{
    const int us = 3000;
    long ms1 = swoole::get_millisecond();
    usleep(us);
    long ms2 = swoole::get_millisecond();
    EXPECT_GE(ms2 - ms1, us / 1000);
}

TEST(time, get_ms_steady)
{
    const int us = 3000;
    long ms1 = swoole::get_millisecond(true);
    usleep(us);
    long ms2 = swoole::get_millisecond(true);
    EXPECT_GE(ms2 - ms1, us / 1000);
}
