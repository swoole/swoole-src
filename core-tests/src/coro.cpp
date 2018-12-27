#include "tests.h"

using namespace swoole;

TEST(coroutine, create)
{
    long cid = Coroutine::create([](void *arg)
    {
        long cid = Coroutine::get_current_cid();
        Coroutine *co = Coroutine::get_by_cid(cid);
        co->yield();
    });
    ASSERT_GT(cid, 0);
    Coroutine::get_by_cid(cid)->resume();
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
        set_dns_cache_capacity(10);

        std::string addr1 = Coroutine::gethostbyname("www.baidu.com", AF_INET);
        std::string addr2 = Coroutine::gethostbyname("www.baidu.com", AF_INET);

        ASSERT_NE(addr1, "");
        ASSERT_NE(addr2, "");
        ASSERT_EQ(addr1, addr2);
    });
}

TEST(coroutine, socket_resolve_without_cache)
{
    coro_test([](void *arg)
    {
        set_dns_cache_capacity(0);

        std::string addr1 = Coroutine::gethostbyname("www.baidu.com", AF_INET);
        std::string addr2 = Coroutine::gethostbyname("www.baidu.com", AF_INET);

        ASSERT_NE(addr1, "");
        ASSERT_NE(addr2, "");
        ASSERT_NE(addr1, addr2);
    });
}

TEST(coroutine, socket_resolve_cache_inet4_and_inet6)
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
