#include "tests.h"

#include <iostream>
#include <regex>

using namespace swoole::coroutine;
using namespace std;

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

TEST(coroutine_async, gethostbyname)
{
    coro_test([](void *arg)
    {
        string domain("www.baidu.com"), ip;

        bool retval = async([&]() {
            char buf[128];
            if (swoole_gethostbyname(AF_INET, domain.c_str(), buf) == SW_OK) {
                char addr[128];
                inet_ntop( AF_INET, buf, addr, sizeof(addr));
                ip = addr;
            } else {
                ip = "unknown";
            }
        });

        ASSERT_EQ(retval, true);
        match_results<string::const_iterator> result;
        const regex pattern("(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3})");
        ASSERT_EQ(regex_match(ip, result, pattern), true);
    });
}
