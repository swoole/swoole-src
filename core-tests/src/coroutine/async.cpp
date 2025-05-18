#include "test_coroutine.h"
#include "swoole_async.h"

#include <iostream>
#include <regex>

using namespace std;
using swoole::AsyncEvent;
using swoole::test::coroutine;

const int magic_code = 0x7009501;

TEST(coroutine_async, usleep) {
    coroutine::run([](void *arg) {
        AsyncEvent ev = {};
        bool retval = swoole::coroutine::async(
            [](AsyncEvent *event) {
                usleep(1000);
                event->retval = magic_code;
            },
            ev);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(ev.retval, magic_code);
    });
}

TEST(coroutine_async, gethostbyname) {
    coroutine::run([](void *arg) {
        string domain("www.baidu.com"), ip;

        bool retval = swoole::coroutine::async([&]() {
            char buf[128];
            if (swoole::network::gethostbyname(AF_INET, domain.c_str(), buf) == SW_OK) {
                char addr[128];
                inet_ntop(AF_INET, buf, addr, sizeof(addr));
                ip = addr;
            } else {
                ip = "unknown";
            }
        });

        ASSERT_EQ(retval, true);
        match_results<string::const_iterator> result;
        try {
            const regex pattern("(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3})");
            ASSERT_EQ(regex_match(ip, result, pattern), true);
        } catch (std::exception &ex) {
            std::cerr << "regex error: gcc version must be 4.9+" << std::endl;
        }
    });
}

TEST(coroutine_async, error) {
    coroutine::run([](void *arg) {
        int retval = 0x7009501;
        const char *test_file = "/tmp/swoole_core_test_file_not_exists";
        swoole::coroutine::async([&](void) { retval = open(test_file, O_RDONLY); });
        ASSERT_EQ(retval, -1);
        ASSERT_EQ(errno, ENOENT);
    });
}

TEST(coroutine_async, cancel) {
    coroutine::run([](void *arg) {
        AsyncEvent ev = {};
        auto co = swoole::Coroutine::get_current();
        swoole_timer_after(50, [co](TIMER_PARAMS) { co->cancel(); });

        bool retval = swoole::coroutine::async(
            [](AsyncEvent *event) {
                usleep(200000);
                event->retval = magic_code;
            },
            ev);

        ASSERT_EQ(retval, false);
        ASSERT_EQ(ev.error, SW_ERROR_CO_CANCELED);
        DEBUG() << "done\n";
    });
}

TEST(coroutine_async, timeout) {
    coroutine::run([](void *arg) {
        AsyncEvent ev = {};

        bool retval = swoole::coroutine::async(
            [](AsyncEvent *event) {
                usleep(200000);
                event->retval = magic_code;
            },
            ev, 0.1);

        ASSERT_EQ(retval, false);
        ASSERT_EQ(ev.error, SW_ERROR_CO_TIMEDOUT);
        DEBUG() << "done\n";
    });
}
