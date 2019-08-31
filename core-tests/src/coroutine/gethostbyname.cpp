#include "tests.h"

#include "coroutine_system.h"

using swoole::Coroutine;
using swoole::coroutine::System;

TEST(coroutine_gethostbyname, resolve_with_cache)
{
    coro_test([](void *arg)
    {
        System::set_dns_cache_capacity(10);

        std::string addr1 = System::gethostbyname("www.baidu.com", AF_INET);
        ASSERT_NE(addr1, "");

        int64_t start = swTimer_get_absolute_msec();

        for (int i = 0; i < 100; ++i)
        {
            std::string addr2 = System::gethostbyname("www.baidu.com", AF_INET);
            ASSERT_EQ(addr1, addr2);
        }

        ASSERT_LT(swTimer_get_absolute_msec() - start, 5);
    });
}

TEST(coroutine_gethostbyname, resolve_without_cache)
{
    coro_test([](void *arg)
    {
        System::set_dns_cache_capacity(0);

        std::string addr1 = System::gethostbyname("www.baidu.com", AF_INET);
        ASSERT_NE(addr1, "");

        int64_t start = swTimer_get_absolute_msec();

        for (int i = 0; i < 5; ++i)
        {
            std::string addr2 = System::gethostbyname("www.baidu.com", AF_INET);
            ASSERT_NE(addr2, "");
        }

        ASSERT_GT(swTimer_get_absolute_msec() - start, 5);
    });
}

TEST(coroutine_gethostbyname, resolve_cache_inet4_and_inet6)
{
    coro_test([](void *arg) 
    {
        System::set_dns_cache_capacity(10);

        std::string addr1 = System::gethostbyname("ipv6.sjtu.edu.cn", AF_INET);
        std::string addr2 = System::gethostbyname("ipv6.sjtu.edu.cn", AF_INET6);

        ASSERT_NE(addr1, "");
        ASSERT_NE(addr2, "");
        ASSERT_EQ(addr1.find(":"), addr1.npos);
        ASSERT_NE(addr2.find(":"), addr2.npos);

        int64_t start = swTimer_get_absolute_msec();

        for (int i = 0; i < 100; ++i)
        {
            std::string addr3 = System::gethostbyname("ipv6.sjtu.edu.cn", AF_INET);
            std::string addr4 = System::gethostbyname("ipv6.sjtu.edu.cn", AF_INET6);

            ASSERT_EQ(addr1, addr3);
            ASSERT_EQ(addr2, addr4);
        }

        ASSERT_LT(swTimer_get_absolute_msec() - start, 5);
    });
}
