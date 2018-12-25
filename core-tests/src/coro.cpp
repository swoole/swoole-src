#include "tests.h"

using namespace swoole;

TEST(coroutine, create)
{
    long cid = Coroutine::create([](void *arg)
    {
        long cid = coroutine_get_current_cid();
        Coroutine *co = coroutine_get_by_id(cid);
        co->yield();
    });
    ASSERT_GT(cid, 0);
    coroutine_get_by_id(cid)->resume();
}

TEST(coroutine, socket_connect_refused)
{
    coro_test([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9801, 0.5);
        ASSERT_EQ(retval, false);
        ASSERT_EQ(sock.errCode, ECONNREFUSED);
    });
}

TEST(coroutine, socket_connect_timeout)
{
    coro_test([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        sock.set_timeout(0.5);
        bool retval = sock.connect("192.0.0.1", 9801);
        ASSERT_EQ(retval, false);
        ASSERT_EQ(sock.errCode, ETIMEDOUT);
    });
}

TEST(coroutine, socket_connect_with_dns)
{
    coro_test([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("www.baidu.com", 80, 0.5);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
    });
}

TEST(coroutine, socket_resolve_with_cache)
{
    coro_test([](void *arg)
    {
        SwooleG.dns_cache_refresh_time = 60;

        Socket sock(SW_SOCK_TCP);
        std::string addr1 = sock.resolve("www.baidu.com");
        std::string addr2 = sock.resolve("www.baidu.com");

        ASSERT_NE(addr1, "");
        ASSERT_NE(addr2, "");
        ASSERT_EQ(addr1, addr2);
    });
}

TEST(coroutine, socket_resolve_without_cache)
{
    coro_test([](void *arg)
    {
        SwooleG.dns_cache_refresh_time = 60;

        Socket sock(SW_SOCK_TCP);
        std::string addr1 = sock.resolve("www.baidu.com");
        std::string addr2 = sock.resolve("www.baidu.com");

        ASSERT_NE(addr1, "");
        ASSERT_NE(addr2, "");
        ASSERT_NE(addr1, addr2);
    });
}

TEST(coroutine, socket_resolve_cache_inet4_and_inet6)
{
    coro_test([](void *arg)
    {
        SwooleG.dns_cache_refresh_time = 60;

        Socket sock(SW_SOCK_TCP);
        std::string addr1 = sock.resolve("ipv6.sjtu.edu.cn");
        Socket sock2(SW_SOCK_TCP6);
        std::string addr2 = sock2.resolve("ipv6.sjtu.edu.cn");

        ASSERT_NE(addr1, "");
        ASSERT_NE(addr2, "");
        ASSERT_EQ(addr1.find(":"), addr1.npos);
        ASSERT_NE(addr2.find(":"), addr2.npos);

        std::string addr3 = sock.resolve("ipv6.sjtu.edu.cn");
        std::string addr4 = sock2.resolve("ipv6.sjtu.edu.cn");

        ASSERT_EQ(addr1, addr3);
        ASSERT_EQ(addr2, addr4);
    });
}

TEST(coroutine, socket_recv_success)
{
    coro_test([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9501, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
        sock.send("echo", 5);
        char buf[128];
        int n = sock.recv(buf, sizeof(buf));
        ASSERT_EQ(strcmp(buf, "hello world\n"), 0);
    });
}

TEST(coroutine, socket_recv_fail)
{
    coro_test([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9501, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
        sock.send("close", 6);
        char buf[128];
        int n = sock.recv(buf, sizeof(buf));
        ASSERT_EQ(n, 0);
    });
}

TEST(coroutine, socket_bind_success)
{
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.bind("127.0.0.1", 9909);
    ASSERT_EQ(retval, true);
}

TEST(coroutine, socket_bind_fail)
{
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.bind("192.111.11.1", 9909);
    ASSERT_EQ(retval, false);
    ASSERT_EQ(sock.errCode, EADDRNOTAVAIL);
}

TEST(coroutine, socket_listen)
{
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.bind("127.0.0.1", 9909);
    ASSERT_EQ(retval, true);
    ASSERT_EQ(sock.listen(128), true);
}

TEST(coroutine, socket_accept)
{
    coroutine_func_t fns[2];
    /**
     * Accept
     */
    fns[0] = [](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", 9909);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.listen(128), true);

        Socket *conn = sock.accept();
        ASSERT_NE(conn, nullptr);
    };

    /**
     * Connect
     */
    fns[1] = [](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9909, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
    };

    coro_test(fns, 2);
}
