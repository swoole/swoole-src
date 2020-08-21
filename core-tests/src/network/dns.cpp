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
using namespace swoole::test;
using namespace std;

TEST(dns, lookup) {
    test::coroutine::run([](void *arg) {
        auto list = swoole::coroutine::dns_lookup("www.baidu.com", 10);
        ASSERT_GE(list.size(), 1);
    });
}

TEST(dns, getaddrinfo) {
    char buf[1024] = { };
    swRequest_getaddrinfo req = { };
    req.hostname = "www.baidu.com";
    req.family = AF_INET;
    req.socktype = SOCK_STREAM;
    req.protocol = 0;
    req.service = nullptr;
    req.result = buf;
    ASSERT_EQ(network::getaddrinfo(&req), 0);
    ASSERT_GT(req.count, 0);

    vector<string> ip_list;
    req.parse_result(ip_list);

    for (auto &ip : ip_list) {
        ASSERT_TRUE(swoole::network::Address::verify_ip(AF_INET, ip));
    }
}
