#include <gtest/gtest.h>
#include "swoole.h"
#include "coro_test.h"

TEST(Coroutine, Create)
{
    EXPECT_LT(0, swoole_test::coroutine_create_test1());
}

TEST(Coroutine, SocketConnect01)
{
    swoole_test::coroutine_socket_connect_refused();
}

TEST(Coroutine, SocketConnect02)
{
    swoole_test::coroutine_socket_connect_timeout();
}

TEST(Coroutine, SocketConnect03)
{
    swoole_test::coroutine_socket_connect_with_dns();
}

TEST(Coroutine, SocketRecv01)
{
    swoole_test::coroutine_socket_recv_success();
}

TEST(Coroutine, SocketRecv02)
{
    swoole_test::coroutine_socket_recv_fail();
}

TEST(Coroutine, SocketBind01)
{
    swoole_test::coroutine_socket_bind_success();
}

TEST(Coroutine, SocketBind02)
{
    swoole_test::coroutine_socket_bind_fail();
}

TEST(Coroutine, SocketListen)
{
    swoole_test::coroutine_socket_listen();
}

TEST(Coroutine, SocketAccept)
{
    swoole_test::coroutine_socket_accept();
}

// TEST(Server, Create)
// {
//     EXPECT_EQ(0, swoole_test::server_test());
// }

int main(int argc, char **argv)
{
    swoole_init();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
