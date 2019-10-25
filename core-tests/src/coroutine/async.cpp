#include "tests.h"

using namespace swoole::coroutine;

const int magic_code = 0x7009501;

TEST(coroutine_async, usleep)
{
    coro_test([](void *arg)
    {
        swAio_event ev;
        bool retval = async([](swAio_event *event) {
            usleep(1000);
            event->ret = magic_code;
        }, ev);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(ev.ret, magic_code);
    });
}
