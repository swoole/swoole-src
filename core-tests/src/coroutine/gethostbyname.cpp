#include "tests.h"

using namespace swoole;

TEST(coroutine_gethostbyname, resolve_with_cache)
{
    coro_test([](void *arg)
    {
        set_dns_cache_capacity(10);

        // TODO: Calculate the time spent, don't compare ip
        std::string addr1 = Coroutine::gethostbyname("www.baidu.com", AF_INET);
        std::string addr2 = Coroutine::gethostbyname("www.baidu.com", AF_INET);

        ASSERT_NE(addr1, "");
        ASSERT_NE(addr2, "");
        ASSERT_EQ(addr1, addr2);
    });
}



TEST(coroutine_gethostbyname, resolve_cache_inet4_and_inet6)
{
    coro_test([](void *arg)
    {
        set_dns_cache_capacity(10);

        std::string addr1 = Coroutine::gethostbyname("ipv6.sjtu.edu.cn", AF_INET);
        std::string addr2 = Coroutine::gethostbyname("ipv6.sjtu.edu.cn", AF_INET6);

        ASSERT_NE(addr1, "");
        ASSERT_NE(addr2, "");
        ASSERT_EQ(addr1.find(":"), addr1.npos);
        ASSERT_NE(addr2.find(":"), addr2.npos);

        std::string addr3 = Coroutine::gethostbyname("ipv6.sjtu.edu.cn", AF_INET);
        std::string addr4 = Coroutine::gethostbyname("ipv6.sjtu.edu.cn", AF_INET6);

        ASSERT_EQ(addr1, addr3);
        ASSERT_EQ(addr2, addr4);
    });
}