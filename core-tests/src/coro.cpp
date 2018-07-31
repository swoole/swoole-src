#include "tests.h"

using namespace swoole;

static void coro1(void *arg)
{
    int cid = coroutine_get_cid();
    coroutine_t *co = coroutine_get_by_id(cid);
    coroutine_yield(co);
}

TEST(coroutine, create)
{
    int cid = coroutine_create(coro1, NULL);
    ASSERT_GT(cid, 0);
    coroutine_resume(coroutine_get_by_id(cid));
}

static void coro2(void *arg)
{
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.connect("127.0.0.1", 9801, 0.5);
    ASSERT_EQ(retval, false);
    ASSERT_EQ(sock.errCode, ECONNREFUSED);
}

TEST(coroutine, socket_connect_refused)
{
    int cid = coroutine_create(coro2, NULL);
    if (cid < 0)
    {
        return;
    }
    SwooleG.main_reactor->wait(SwooleG.main_reactor, nullptr);
}

static void coro3(void *arg)
{
    Socket sock(SW_SOCK_TCP);
    sock.setTimeout(0.5);
    bool retval = sock.connect("192.0.0.1", 9801);
    ASSERT_EQ(retval, false);
    ASSERT_EQ(sock.errCode, ETIMEDOUT);
}

TEST(coroutine, socket_connect_timeout)
{
    int cid = coroutine_create(coro3, NULL);
    if (cid < 0)
    {
        return;
    }
    SwooleG.main_reactor->wait(SwooleG.main_reactor, nullptr);
}

static void coro4(void *arg)
{
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.connect("www.baidu.com", 80, 0.5);
    ASSERT_EQ(retval, true);
    ASSERT_EQ(sock.errCode, 0);
}

TEST(coroutine, socket_connect_with_dns)
{
    int cid = coroutine_create(coro4, NULL);
    if (cid < 0)
    {
        return;
    }
    SwooleG.main_reactor->wait(SwooleG.main_reactor, nullptr);
}

static void coro5(void *arg)
{
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.connect("127.0.0.1", 9501, -1);
    ASSERT_EQ(retval, true);
    ASSERT_EQ(sock.errCode, 0);
    sock.send("echo", 5);
    char buf[128];
    int n = sock.recv(buf, sizeof(buf));
    ASSERT_EQ(strcmp(buf, "hello world\n"), 0);
}

TEST(coroutine, socket_recv_success)
{
    int cid = coroutine_create(coro5, NULL);
    if (cid < 0)
    {
        return;
    }
    SwooleG.main_reactor->wait(SwooleG.main_reactor, nullptr);
}

static void coro6(void *arg)
{
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.connect("127.0.0.1", 9501, -1);
    ASSERT_EQ(retval, true);
    ASSERT_EQ(sock.errCode, 0);
    sock.send("close", 6);
    char buf[128];
    int n = sock.recv(buf, sizeof(buf));
    ASSERT_EQ(n, 0);
}

TEST(coroutine, socket_recv_fail)
{
    int cid = coroutine_create(coro6, NULL);
    if (cid < 0)
    {
        return;
    }
    SwooleG.main_reactor->wait(SwooleG.main_reactor, nullptr);
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

/**
 * Accept
 */
static void coro7(void *arg)
{
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.bind("127.0.0.1", 9909);
    ASSERT_EQ(retval, true);
    ASSERT_EQ(sock.listen(128), true);

    Socket *conn = sock.accept();
    ASSERT_NE(conn, nullptr);
}

/**
 * Connect
 */
static void coro8(void *arg)
{
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.connect("127.0.0.1", 9909, -1);
    ASSERT_EQ(retval, true);
    ASSERT_EQ(sock.errCode, 0);
}

TEST(coroutine, socket_accept)
{
    coroutine_create(coro7, NULL);
    coroutine_create(coro8, NULL);
    SwooleG.main_reactor->wait(SwooleG.main_reactor, nullptr);
}

