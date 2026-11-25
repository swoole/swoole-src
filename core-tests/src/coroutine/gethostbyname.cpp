#include "test_coroutine.h"

#include <atomic>

using swoole::Coroutine;
using swoole::Timer;
using swoole::coroutine::System;
using swoole::test::coroutine;

TEST(coroutine_gethostbyname, resolve_cache) {
    coroutine::run([](void *arg) {
        System::set_dns_cache_capacity(10);
        std::string addr1 = System::gethostbyname(TEST_DOMAIN_BAIDU, AF_INET);
        ASSERT_NE(addr1, "");
        for (int i = 0; i < 100; ++i) {
            std::string addr2 = System::gethostbyname(TEST_DOMAIN_BAIDU, AF_INET);
            ASSERT_EQ(addr1, addr2);
        }
        ASSERT_GT(System::get_dns_cache_hit_ratio(), 0.99);

        System::set_dns_cache_capacity(0);
        for (int i = 0; i < 5; ++i) {
            std::string addr2 = System::gethostbyname(TEST_DOMAIN_BAIDU, AF_INET);
            ASSERT_NE(addr2, "");
        }
        ASSERT_LT(System::get_dns_cache_hit_ratio(), 0.01);
    });
}

TEST(coroutine_gethostbyname, concurrent_cache_reconfiguration) {
    System::set_dns_cache_capacity(2);
    ON_SCOPE_EXIT {
        System::set_dns_cache_capacity(1000);
        System::set_dns_cache_expire(60);
    };

    std::atomic<bool> running{true};
    std::atomic<bool> reconfigured{false};
    std::thread configure([&] {
        do {
            System::set_dns_cache_capacity(0);
            System::set_dns_cache_expire(60);
            System::set_dns_cache_capacity(2);
            System::clear_dns_cache();
            const float ratio = System::get_dns_cache_hit_ratio();
            EXPECT_GE(ratio, 0);
            EXPECT_LE(ratio, 1);
            reconfigured = true;
            std::this_thread::yield();
        } while (running);
    });
    ON_SCOPE_EXIT {
        running = false;
        configure.join();
    };
    while (!reconfigured) {
        std::this_thread::yield();
    }

    coroutine::run([](void *) {
        for (int i = 0; i < 200; ++i) {
            const char *address = i % 2 == 0 ? "127.0.0.1" : "127.0.0.2";
            ASSERT_EQ(System::gethostbyname(address, AF_INET, 2), address);
        }
    });

#ifndef _WIN32
    // The child must be able to acquire the cache lock even while another thread is configuring it.
    pid_t pid = fork();
    if (pid == 0) {
        alarm(2);
        System::clear_dns_cache();
        _exit(0);
    }
    ASSERT_GT(pid, 0);
    int status;
    ASSERT_EQ(swoole_waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
#endif
}

TEST(coroutine_gethostbyname, impl_async) {
    coroutine::run([](void *arg) {
        auto result = swoole::coroutine::gethostbyname_impl_with_async(TEST_DOMAIN_BAIDU, AF_INET);
        ASSERT_EQ(result.empty(), false);
    });
}

TEST(coroutine_gethostbyname, resolve_cache_inet4_and_inet6) {
    coroutine::run([](void *arg) {
        System::set_dns_cache_capacity(10);

        std::string addr1 = System::gethostbyname("ipv6.sjtu.edu.cn", AF_INET);
        std::string addr2 = System::gethostbyname("ipv6.sjtu.edu.cn", AF_INET6);

        ASSERT_NE(addr1, "");
        ASSERT_NE(addr2, "");
        ASSERT_EQ(addr1.find(":"), addr1.npos);
        ASSERT_NE(addr2.find(":"), addr2.npos);

        int64_t start = Timer::get_absolute_msec();

        for (int i = 0; i < 100; ++i) {
            std::string addr3 = System::gethostbyname("ipv6.sjtu.edu.cn", AF_INET);
            std::string addr4 = System::gethostbyname("ipv6.sjtu.edu.cn", AF_INET6);

            ASSERT_EQ(addr1, addr3);
            ASSERT_EQ(addr2, addr4);
        }

        ASSERT_LT(Timer::get_absolute_msec() - start, 5);
    });
}

TEST(coroutine_gethostbyname, dns_expire) {
    coroutine::run([](void *arg) {
        System::set_dns_cache_expire(1);
        System::clear_dns_cache();

        System::gethostbyname(TEST_HTTP_DOMAIN, AF_INET);
        System::gethostbyname(TEST_HTTP_DOMAIN, AF_INET);
        ASSERT_GE(System::get_dns_cache_hit_ratio(), 0.5);

        sleep(2);
        System::gethostbyname(TEST_HTTP_DOMAIN, AF_INET);
        ASSERT_LT(System::get_dns_cache_hit_ratio(), 0.35);

        System::clear_dns_cache();
        System::set_dns_cache_expire(60);
    });
}
