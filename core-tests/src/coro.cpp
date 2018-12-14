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
    CORO_TEST_START(connect)
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9801, 0.5);
        ASSERT_EQ(retval, false);
        ASSERT_EQ(sock.errCode, ECONNREFUSED);
    CORO_TEST_END(connect)

    CORO_TEST_WAIT(connect)
}

TEST(coroutine, socket_connect_timeout)
{
    CORO_TEST_START(connect)
        Socket sock(SW_SOCK_TCP);
        sock.set_timeout(0.5);
        bool retval = sock.connect("192.0.0.1", 9801);
        ASSERT_EQ(retval, false);
        ASSERT_EQ(sock.errCode, ETIMEDOUT);
    CORO_TEST_END(connect)

    CORO_TEST_WAIT(connect)
}

TEST(coroutine, socket_connect_with_dns)
{
    CORO_TEST_START(connect)
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("www.baidu.com", 80, 0.5);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
    CORO_TEST_END(connect)

    CORO_TEST_WAIT(connect)
}

TEST(coroutine, socket_recv_success)
{
    CORO_TEST_START(recv)
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9501, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
        sock.send("echo", 5);
        char buf[128];
        int n = sock.recv(buf, sizeof(buf));
        ASSERT_EQ(strcmp(buf, "hello world\n"), 0);
    CORO_TEST_END(recv)

    CORO_TEST_WAIT(recv)
}

TEST(coroutine, socket_recv_fail)
{
    CORO_TEST_START(recv)
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9501, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
        sock.send("close", 6);
        char buf[128];
        int n = sock.recv(buf, sizeof(buf));
        ASSERT_EQ(n, 0);
    CORO_TEST_END(recv)

    CORO_TEST_WAIT(recv)
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
    /**
     * Accept
     */
    CORO_TEST_START(accept)
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", 9909);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.listen(128), true);

        Socket *conn = sock.accept();
        ASSERT_NE(conn, nullptr);
    CORO_TEST_END(accept)

    /**
     * Connect
     */
    CORO_TEST_START(connect)
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9909, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
    CORO_TEST_END(connect)

    CORO_TEST_WAIT(connect)
    CORO_TEST_WAIT(accept)
}

TEST(coroutine, socket_resolve)
{
    CORO_TEST_START(resolve)
        Socket sock(SW_SOCK_TCP);
        auto retval = sock.resolve("www.swoole.com");
        ASSERT_EQ(retval, "47.244.108.17");
    CORO_TEST_END(resolve)

    CORO_TEST_WAIT(resolve)
}

