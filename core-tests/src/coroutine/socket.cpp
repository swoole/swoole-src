#include "tests.h"
#include "coroutine_socket.h"

using swoole::coroutine::Socket;

TEST(coroutine_socket, connect_refused)
{
    coro_test([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9801, 0.5);
        ASSERT_EQ(retval, false);
        ASSERT_EQ(sock.errCode, ECONNREFUSED);
    });
}

TEST(coroutine_socket, connect_timeout)
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

TEST(coroutine_socket, connect_with_dns)
{
    coro_test([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("www.baidu.com", 80, 0.5);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
    });
}

TEST(coroutine_socket, recv_success)
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

TEST(coroutine_socket, recv_fail)
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

TEST(coroutine_socket, bind_success)
{
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.bind("127.0.0.1", 9909);
    ASSERT_EQ(retval, true);
}

TEST(coroutine_socket, bind_fail)
{
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.bind("192.111.11.1", 9909);
    ASSERT_EQ(retval, false);
    ASSERT_EQ(sock.errCode, EADDRNOTAVAIL);
}

TEST(coroutine_socket, listen)
{
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.bind("127.0.0.1", 9909);
    ASSERT_EQ(retval, true);
    ASSERT_EQ(sock.listen(128), true);
}

TEST(coroutine_socket, accept)
{
    coro_test({
        [](void *arg)
        {
            Socket sock(SW_SOCK_TCP);
            bool retval = sock.bind("127.0.0.1", 9909);
            ASSERT_EQ(retval, true);
            ASSERT_EQ(sock.listen(128), true);

            Socket *conn = sock.accept();
            ASSERT_NE(conn, nullptr);
        },

        [](void *arg)
        {
            Socket sock(SW_SOCK_TCP);
            bool retval = sock.connect("127.0.0.1", 9909, -1);
            ASSERT_EQ(retval, true);
            ASSERT_EQ(sock.errCode, 0);
            sock.close();
        }
    });
}
