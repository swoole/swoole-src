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

#include "test_coroutine.h"

#include "swoole_socket.h"

#include "swoole_util.h"

using namespace swoole;
using swoole::coroutine::Socket;
using swoole::coroutine::System;
using namespace swoole::test;
using namespace std;

TEST(dns, lookup1) {
    test::coroutine::run([](void *arg) {
        auto list = swoole::coroutine::dns_lookup("www.baidu.com", AF_INET, 10);
        ASSERT_GE(list.size(), 1);
    });
}

TEST(dns, lookup_ipv6) {
    test::coroutine::run([](void *arg) {
        auto list = swoole::coroutine::dns_lookup("www.google.com", AF_INET6, 2);
        ASSERT_GE(list.size(), 1);
    });
}

TEST(dns, domain_not_found) {
    test::coroutine::run([](void *arg) {
        auto list = swoole::coroutine::dns_lookup("www.baidu.com-not-found", AF_INET, 2);
        ASSERT_EQ(list.size(), 0);
        ASSERT_EQ(swoole_get_last_error(), SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
    });
}

TEST(dns, bad_family) {
    test::coroutine::run([](void *arg) {
        auto list = swoole::coroutine::dns_lookup("www.google.com", 9999, 2);
        ASSERT_GE(list.size(), 1);
    });
}

TEST(dns, cancel) {
    // swoole_set_trace_flags(SW_TRACE_CARES);
    // swoole_set_log_level(SW_LOG_TRACE);
    test::coroutine::run([](void *arg) {
        auto co = Coroutine::get_current_safe();
        Coroutine::create([co](void *) {
            System::sleep(0.002);
            co->cancel();
        });
        auto list1 = swoole::coroutine::dns_lookup("www.baidu-not-found-for-cancel.com", AF_INET, 2);
        ASSERT_EQ(list1.size(), 0);
        ASSERT_EQ(swoole_get_last_error(), SW_ERROR_CO_CANCELED);
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

TEST(dns, load_resolv_conf) {
    // reset
    SwooleG.dns_server_host = "";
    SwooleG.dns_server_port = 0;

    auto dns_server = swoole_get_dns_server();
    ASSERT_TRUE(dns_server.first.empty());
    ASSERT_EQ(dns_server.second, 0);

    // with port
    std::string test_server = "127.0.0.1:8080";  // fake dns server
    swoole_set_dns_server(test_server);
    dns_server = swoole_get_dns_server();
    ASSERT_STREQ(dns_server.first.c_str(), "127.0.0.1");
    ASSERT_EQ(dns_server.second, 8080);

    // invalid port
    test_server = "127.0.0.1:808088";
    swoole_set_dns_server(test_server);
    dns_server = swoole_get_dns_server();
    ASSERT_EQ(dns_server.second, SW_DNS_SERVER_PORT);

    ASSERT_TRUE(swoole_load_resolv_conf());
    dns_server = swoole_get_dns_server();
    ASSERT_FALSE(dns_server.first.empty());
    ASSERT_NE(dns_server.second, 0);
}

TEST(dns, gethosts) {
    char hosts_file[] = "/tmp/swoole_hosts";
    ofstream file(hosts_file);
    if (!file.is_open()) {
        std::cout << std::string("file open failed: ") + std::string(strerror(errno)) << std::endl;
        throw strerror(errno);
    }

    ON_SCOPE_EXIT {
        unlink(hosts_file);
    };

    file << "\n";
    file << "127.0.0.1\n";
    file << "127.0.0.1 localhost\n";
    file << "# 127.0.0.1 aaa.com\n";
    file << "       127.0.0.1 bbb.com               ccc.com      #ddd.com\n";
    file.close();

    swoole_set_hosts_path(hosts_file);

    std::string ip = swoole::coroutine::get_ip_by_hosts("localhost");
    ASSERT_EQ(ip, "127.0.0.1");

    ip = swoole::coroutine::get_ip_by_hosts("aaa.com");
    ASSERT_EQ(ip, "");

    ip = swoole::coroutine::get_ip_by_hosts("bbb.com");
    ASSERT_EQ(ip, "127.0.0.1");

    ip = swoole::coroutine::get_ip_by_hosts("ccc.com");
    ASSERT_EQ(ip, "127.0.0.1");

    ip = swoole::coroutine::get_ip_by_hosts("ddd.com");
    ASSERT_EQ(ip, "");

    ip = swoole::coroutine::get_ip_by_hosts("non.exist.com");
    ASSERT_EQ(ip, "");
}

void name_resolver_test_fn_1() {
    NameResolver::Context ctx{};
    ctx.type = AF_INET;
    ctx.timeout = 1;
    ASSERT_EQ("127.0.0.1", swoole_name_resolver_lookup("localhost", &ctx));
}

void name_resolver_test_fn_2() {
    NameResolver::Context ctx;
    std::string domain = "non.exist.com";
    NameResolver nr{[](const std::string &domain, NameResolver::Context *ctx, void *) -> std::string {
                        if (domain == "name1") {
                            return "127.0.0.2";
                        } else if (domain == "www.baidu.com") {
                            ctx->final_ = true;
                            return "";
                        }
                        return "";
                    },
                    nullptr,
                    NameResolver::TYPE_USER};

    swoole_name_resolver_add(nr);

    ctx = {AF_INET};
    ASSERT_EQ("127.0.0.2", swoole_name_resolver_lookup("name1", &ctx));

    ctx = {AF_INET};
    ASSERT_EQ("", swoole_name_resolver_lookup("www.baidu.com", &ctx));

    ctx = {AF_INET};
    ASSERT_EQ("127.0.0.1", swoole_name_resolver_lookup("localhost", &ctx));

    swoole_name_resolver_each([](const std::list<NameResolver>::iterator &iter) -> swTraverseOperation {
        if (iter->type == NameResolver::TYPE_USER) {
            return SW_TRAVERSE_REMOVE;
        } else {
            return SW_TRAVERSE_KEEP;
        }
    });

    ctx = {AF_INET};
    auto ip = swoole_name_resolver_lookup("www.baidu.com", &ctx);
    ASSERT_TRUE(swoole::network::Address::verify_ip(AF_INET, ip));
}

TEST(dns, name_resolver_1) {
    name_resolver_test_fn_1();
    test::coroutine::run([](void *arg) { name_resolver_test_fn_1(); });
}

TEST(dns, name_resolver_2) {
    name_resolver_test_fn_2();
    test::coroutine::run([](void *arg) { name_resolver_test_fn_2(); });
}
