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

#include <atomic>

using namespace swoole;
using swoole::coroutine::Socket;
using swoole::coroutine::System;
using namespace swoole::test;

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
            System::sleep(0.001);
            co->cancel();
        });
        auto list1 = swoole::coroutine::dns_lookup("www.baidu-not-found-for-cancel.com", AF_INET, 2);
        ASSERT_EQ(list1.size(), 0);
        ASSERT_EQ(swoole_get_last_error(), SW_ERROR_CO_CANCELED);
    });
}

TEST(dns, gethostbyname) {
    GethostbynameRequest req1(TEST_HTTP_DOMAIN, AF_INET);
    ASSERT_EQ(network::gethostbyname(&req1), 0);
    ASSERT_TRUE(network::Address::verify_ip(AF_INET, req1.addr));

    GethostbynameRequest req2(TEST_HTTP_DOMAIN, AF_INET6);
    ASSERT_EQ(network::gethostbyname(&req2), 0);
    ASSERT_TRUE(network::Address::verify_ip(AF_INET6, req2.addr));
}

TEST(dns, getaddrinfo) {
    GetaddrinfoRequest req("www.baidu.com", AF_INET, SOCK_STREAM, 0, "");
    ASSERT_EQ(network::getaddrinfo(&req), 0);
    ASSERT_GT(req.count, 0);

    std::vector<std::string> ip_list;
    req.parse_result(ip_list);

    for (auto &ip : ip_list) {
        ASSERT_TRUE(network::Address::verify_ip(AF_INET, ip));
    }
}

TEST(dns, getaddrinfo_fail) {
    GetaddrinfoRequest req("www.baidu.com-not-exists", AF_INET, SOCK_STREAM, 0, "");
    ASSERT_EQ(network::getaddrinfo(&req), -1);
    ASSERT_EQ(req.error, EAI_NONAME);
}

TEST(dns, getaddrinfo_ipv6) {
    GetaddrinfoRequest req(TEST_HTTP_DOMAIN, AF_INET6, SOCK_STREAM, 0, "");
    ASSERT_EQ(network::getaddrinfo(&req), 0);
    ASSERT_GT(req.count, 0);

    DEBUG() << "result count: " << req.count << std::endl;

    std::vector<std::string> ip_list;
    req.parse_result(ip_list);

    for (auto &ip : ip_list) {
        ASSERT_TRUE(network::Address::verify_ip(AF_INET6, ip));
    }
}

TEST(dns, load_resolv_conf) {
    int port = get_random_port();

    auto ori_dns_server = swoole_get_dns_server();

    // with port
    std::string test_server = "127.0.0.1:" + std::to_string(port);  // fake dns server
    swoole_set_dns_server(test_server);
    auto dns_server = swoole_get_dns_server();
    ASSERT_STREQ(dns_server.host.c_str(), "127.0.0.1");
    ASSERT_EQ(dns_server.port, port);

    // invalid port
    test_server = "127.0.0.1:808088";
    swoole_set_dns_server(test_server);
    dns_server = swoole_get_dns_server();
    ASSERT_EQ(dns_server.port, SW_DNS_SERVER_PORT);

    ASSERT_TRUE(swoole_load_resolv_conf());
    dns_server = swoole_get_dns_server();
    ASSERT_EQ(dns_server.host, ori_dns_server.host);
    ASSERT_EQ(dns_server.port, ori_dns_server.port);
}

TEST(dns, load_resolv_conf_empty_nameserver) {
    std::string resolv_conf = "/tmp/swoole_resolv_conf_empty." + std::to_string(getpid());
    std::ofstream file(resolv_conf);
    ASSERT_TRUE(file.is_open());
    file << "nameserver\n";
    file.close();

    auto ori_path = SwooleG.dns_resolvconf_path;
    auto ori_dns_server = SwooleG.dns_server;
    ON_SCOPE_EXIT {
        SwooleG.dns_resolvconf_path = ori_path;
        SwooleG.dns_server = ori_dns_server;
        unlink(resolv_conf.c_str());
    };

    SwooleG.dns_resolvconf_path = resolv_conf;
    ASSERT_FALSE(swoole_load_resolv_conf());
}

TEST(dns, load_resolv_conf_long_nameserver) {
    std::string resolv_conf = "/tmp/swoole_resolv_conf_long." + std::to_string(getpid());
    std::ofstream file(resolv_conf);
    ASSERT_TRUE(file.is_open());
    file << "nameserver " << std::string(256, '1') << "\n";
    file.close();

    auto ori_path = SwooleG.dns_resolvconf_path;
    auto ori_dns_server = SwooleG.dns_server;
    ON_SCOPE_EXIT {
        SwooleG.dns_resolvconf_path = ori_path;
        SwooleG.dns_server = ori_dns_server;
        unlink(resolv_conf.c_str());
    };

    SwooleG.dns_resolvconf_path = resolv_conf;
    ASSERT_TRUE(swoole_load_resolv_conf());
    ASSERT_LT(SwooleG.dns_server.host.size(), 32);
}

TEST(dns, getaddrinfo_result_limit) {
    GetaddrinfoRequest req("localhost", AF_UNSPEC, SOCK_STREAM, 0, "http");
    ASSERT_EQ(network::getaddrinfo(&req), 0);
    ASSERT_LE(req.count, SW_DNS_HOST_BUFFER_SIZE);
    ASSERT_EQ(req.results.size(), static_cast<size_t>(req.count));
}

TEST(dns, lookup_with_too_long_label) {
    auto ori_dns_server = SwooleG.dns_server;
    ON_SCOPE_EXIT {
        SwooleG.dns_server = ori_dns_server;
    };

    SwooleG.dns_server.host = "127.0.0.1";
    SwooleG.dns_server.port = get_random_port();

    auto result = swoole::coroutine::dns_lookup_impl_with_socket((std::string(64, 'a') + ".com").c_str(), AF_INET, 1);
    ASSERT_TRUE(result.empty());
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
}

TEST(dns, lookup_with_malformed_response) {
    auto ori_dns_server = SwooleG.dns_server;
    int port = get_random_port();
    std::atomic<bool> server_error{false};
    std::mutex m;
    m.lock();

    std::thread server_thread([&]() {
        int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            server_error = true;
            m.unlock();
            return;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
            server_error = true;
            m.unlock();
            close(fd);
            return;
        }
        m.unlock();

        char buf[512];
        sockaddr_in client_addr{};
        socklen_t client_addr_len = sizeof(client_addr);
        ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&client_addr), &client_addr_len);
        if (n > 0) {
            const char malformed_response[2] = {};
            ::sendto(fd,
                     malformed_response,
                     sizeof(malformed_response),
                     0,
                     reinterpret_cast<sockaddr *>(&client_addr),
                     client_addr_len);
        }
        close(fd);
    });

    ON_SCOPE_EXIT {
        SwooleG.dns_server = ori_dns_server;
        server_thread.join();
    };

    m.lock();
    m.unlock();
    ASSERT_FALSE(server_error);

    SwooleG.dns_server.host = "127.0.0.1";
    SwooleG.dns_server.port = port;

    test::coroutine::run([](void *) {
        auto result = swoole::coroutine::dns_lookup_impl_with_socket("example.com", AF_INET, 1);
        ASSERT_TRUE(result.empty());
        ASSERT_EQ(swoole_get_last_error(), SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
    });
}

TEST(dns, gethosts) {
    char hosts_file[] = "/tmp/swoole_hosts";
    std::ofstream file(hosts_file);
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

TEST(dns, name_resolve_1) {
    name_resolver_test_fn_1();
    test::coroutine::run([](void *arg) { name_resolver_test_fn_1(); });
}

TEST(dns, name_resolve_2) {
    name_resolver_test_fn_2();
    test::coroutine::run([](void *arg) { name_resolver_test_fn_2(); });
}

TEST(dns, name_resolve_fail) {
    NameResolver::Context ctx;
    ctx = {AF_INET};
    auto ip = swoole_name_resolver_lookup("www.baidu.com-not-exists", &ctx);
    ASSERT_TRUE(ip.empty());
    ASSERT_ERREQ(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
}
