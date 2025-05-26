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
  | @Author   Tianfeng Han  <rango@swoole.com>                           |
  +----------------------------------------------------------------------+
*/

#include "test_core.h"

using swoole::network::Address;

TEST(address, basic) {
    Address address{};
    ASSERT_TRUE(address.empty());
    ASSERT_TRUE(address.assign(SW_SOCK_TCP, TEST_DOMAIN_BAIDU, 80, true));
    address.set_port(443);
    ASSERT_EQ(address.get_port(), 443);
}

TEST(address, dns_fail) {
    Address address{};
    ASSERT_FALSE(address.assign(SW_SOCK_TCP, TEST_DOMAIN_BAIDU "not-exists", 80, true));
    ASSERT_ERREQ(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
}

TEST(address, path_to_long) {
    Address address{};
    swoole::String path;
    path.repeat("HELLO", 5, 128);
    ASSERT_FALSE(address.assign(SW_SOCK_UNIX_DGRAM, path.to_std_string()));
    ASSERT_ERREQ(SW_ERROR_NAME_TOO_LONG);
}

TEST(address, bad_type) {
    Address address{};
    ASSERT_FALSE(address.assign((swSocketType)(SW_SOCK_RAW6 + 9), TEST_DOMAIN_BAIDU));
    ASSERT_ERREQ(SW_ERROR_BAD_SOCKET_TYPE);
}

TEST(address, type_str) {
    ASSERT_STREQ(Address::type_str(SW_SOCK_TCP), "IPv4");
    ASSERT_STREQ(Address::type_str(SW_SOCK_UNIX_STREAM), "UnixSocket");
    ASSERT_STREQ(Address::type_str(SW_SOCK_TCP6), "IPv6");
    ASSERT_STREQ(Address::type_str((swSocketType)(SW_SOCK_RAW6 + 9)), "Unknown");
}

TEST(address, is_loopback_addr) {
    Address address{};
    ASSERT_TRUE(address.assign(SW_SOCK_TCP, TEST_DOMAIN_BAIDU, 80, true));
    ASSERT_FALSE(address.is_loopback_addr());

    ASSERT_TRUE(address.assign(SW_SOCK_TCP, TEST_HOST, 80, true));
    ASSERT_TRUE(address.is_loopback_addr());

    ASSERT_TRUE(address.assign(SW_SOCK_TCP6, "::1", 80, true));
    ASSERT_TRUE(address.is_loopback_addr());

    ASSERT_TRUE(address.assign(SW_SOCK_TCP6, TEST_HTTP_DOMAIN, 443, true));
    ASSERT_FALSE(address.is_loopback_addr());

    ASSERT_TRUE(address.assign(SW_SOCK_UNIX_DGRAM, TEST_LOG_FILE));
    ASSERT_FALSE(address.is_loopback_addr());
}

TEST(address, ipv4_addr) {
    auto sock = swoole::make_socket(SW_SOCK_TCP, SW_FD_STREAM, 0);
    Address addr;

    ASSERT_TRUE(addr.assign("tcp://127.0.0.1:12345"));
    ASSERT_EQ(sock->connect(addr), SW_ERR);
    ASSERT_EQ(errno, ECONNREFUSED);

    ASSERT_TRUE(addr.assign("tcp://localhost:12345"));
    ASSERT_EQ(sock->connect(addr), SW_ERR);
    ASSERT_EQ(errno, ECONNREFUSED);

    sock->free();
}

TEST(address, ipv6_addr) {
    auto sock = swoole::make_socket(SW_SOCK_TCP6, SW_FD_STREAM, 0);
    Address addr;

    ASSERT_TRUE(addr.assign("tcp://[::1]:12345"));
    ASSERT_EQ(sock->connect(addr), SW_ERR);
    ASSERT_EQ(errno, ECONNREFUSED);

    ASSERT_TRUE(addr.assign("tcp://[ip6-localhost]:12345"));
    ASSERT_EQ(sock->connect(addr), SW_ERR);
    ASSERT_EQ(errno, ECONNREFUSED);

    sock->free();
}

TEST(address, unix_addr) {
    auto sock = swoole::make_socket(SW_SOCK_UNIX_STREAM, SW_FD_STREAM, 0);
    Address addr;
    ASSERT_TRUE(addr.assign("unix:///tmp/swoole-not-exists.sock"));
    ASSERT_EQ(sock->connect(addr), SW_ERR);
    ASSERT_EQ(errno, ENOENT);
    sock->free();
}

TEST(address, bad_addr) {
    Address addr;
    ASSERT_FALSE(addr.assign("test://[::1]:12345"));
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_BAD_HOST_ADDR);
}

TEST(address, bad_port) {
    Address addr;
    ASSERT_FALSE(addr.assign("tcp://[::1]:92345"));
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_BAD_PORT);
}

TEST(address, loopback_addr) {
    Address addr1;
    addr1.assign(SW_SOCK_TCP, "127.0.0.1", 0);
    ASSERT_TRUE(addr1.is_loopback_addr());

    Address addr2;
    addr2.assign(SW_SOCK_TCP6, "::1", 0);
    ASSERT_TRUE(addr1.is_loopback_addr());

    Address addr3;
    addr3.assign(SW_SOCK_TCP, "192.168.1.2", 0);
    ASSERT_FALSE(addr3.is_loopback_addr());

    Address addr4;
    addr4.assign(SW_SOCK_TCP6, "192::66::88", 0);
    ASSERT_FALSE(addr4.is_loopback_addr());
}