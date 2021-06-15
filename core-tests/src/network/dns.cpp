/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | @link     https://www.swoole.com/                                    |
  | @contact  team@swoole.com                                            |
  | @license  https://github.com/swoole/swoole-src/blob/master/LICENSE   |
  | @author   Tianfeng Han  <mikan.tenny@gmail.com>                      |
  +----------------------------------------------------------------------+
*/

#include "test_coroutine.h"

#include "swoole_socket.h"

using namespace swoole;
using swoole::coroutine::Socket;
using swoole::coroutine::System;
using namespace swoole::test;
using namespace std;

TEST(dns, lookup) {
    test::coroutine::run([](void *arg) {
        auto list = swoole::coroutine::dns_lookup("www.baidu.com", 10);
        ASSERT_GE(list.size(), 1);
    });
}

TEST(dns, getaddrinfo) {
    char buf[1024] = {};
    swoole::network::GetaddrinfoRequest req = {};
    req.hostname = "www.baidu.com";
    req.family = AF_INET;
    req.socktype = SOCK_STREAM;
    req.protocol = 0;
    req.service = nullptr;
    req.result = buf;
    ASSERT_EQ(swoole::network::getaddrinfo(&req), 0);
    ASSERT_GT(req.count, 0);

    vector<string> ip_list;
    req.parse_result(ip_list);

    for (auto &ip : ip_list) {
        ASSERT_TRUE(swoole::network::Address::verify_ip(AF_INET, ip));
    }
}

#ifdef HAVE_CARES
TEST(dns, gethostbyname_cares) {
    // swoole_set_trace_flags(SW_TRACE_CARES);
    // swoole_set_log_level(SW_LOG_TRACE);
    test::coroutine::run([](void *arg) {
        auto list1 = swoole::coroutine::dns_lookup_ex("www.baidu.com", AF_INET, 2);
        ASSERT_GE(list1.size(), 1);

        auto list2 = swoole::coroutine::dns_lookup_ex("www.baidu.com-not-found", AF_INET, 2);
        ASSERT_EQ(list2.size(), 0);
        ASSERT_EQ(swoole_get_last_error(), SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);

        auto list3 = swoole::coroutine::dns_lookup_ex("www.google.com", AF_INET6, 2);
        ASSERT_GE(list3.size(), 1);

        auto list4 = swoole::coroutine::dns_lookup_ex("www.google.com", 9999, 2);
        ASSERT_GE(list3.size(), 1);
        ASSERT_EQ(swoole_get_last_error(), SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
    });
}

TEST(dns, gethostbyname_cares_cancel) {
    // swoole_set_trace_flags(SW_TRACE_CARES);
    // swoole_set_log_level(SW_LOG_TRACE);
    test::coroutine::run([](void *arg) {
        auto co = Coroutine::get_current_safe();
        Coroutine::create([co](void *){
            System::sleep(0.002);
            co->cancel();
        });
        auto list1 = swoole::coroutine::dns_lookup_ex("www.baidu.com", AF_INET, 2);
        ASSERT_EQ(list1.size(), 0);
        ASSERT_EQ(swoole_get_last_error(), SW_ERROR_CO_CANCELED);
    });
}
#endif
