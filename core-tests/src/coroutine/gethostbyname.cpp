#include "test_coroutine.h"

using swoole::Coroutine;
using swoole::Timer;
using swoole::coroutine::System;
using swoole::test::coroutine;

const char *domain_baidu = "www.baidu.com";
const char *domain_tencent = "www.tencent.com";

TEST(coroutine_gethostbyname, resolve_cache) {
    coroutine::run([](void *arg) {
        System::set_dns_cache_capacity(10);
        std::string addr1 = System::gethostbyname(domain_baidu, AF_INET);
        ASSERT_NE(addr1, "");
        int64_t with_cache = Timer::get_absolute_msec();
        for (int i = 0; i < 100; ++i) {
            std::string addr2 = System::gethostbyname(domain_baidu, AF_INET);
            ASSERT_EQ(addr1, addr2);
        }
        with_cache = Timer::get_absolute_msec() - with_cache;

        System::set_dns_cache_capacity(0);
        int64_t without_cache = Timer::get_absolute_msec();
        for (int i = 0; i < 5; ++i) {
            std::string addr2 = System::gethostbyname(domain_baidu, AF_INET);
            ASSERT_NE(addr2, "");
        }
        without_cache = Timer::get_absolute_msec() - without_cache;

        ASSERT_GT(without_cache, with_cache);
    });
}

TEST(coroutine_gethostbyname, impl_async) {
    coroutine::run([](void *arg) {
        auto result = swoole::coroutine::gethostbyname_impl_with_async(domain_baidu, AF_INET);
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
        time_t expire = 0.2;
        System::set_dns_cache_expire(expire);
        System::gethostbyname(domain_tencent, AF_INET);

        int64_t with_cache = Timer::get_absolute_msec();
        System::gethostbyname(domain_tencent, AF_INET);
        with_cache = Timer::get_absolute_msec() - with_cache;

        sleep(0.3);
        int64_t without_cache = Timer::get_absolute_msec();
        System::gethostbyname(domain_tencent, AF_INET);
        without_cache = Timer::get_absolute_msec() - without_cache;

        ASSERT_GE(without_cache, with_cache);
        System::clear_dns_cache();
    });
}
