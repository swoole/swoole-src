#include "swoole.h"
#include "coroutine.h"
#include "Socket.h"
#include <gtest/gtest.h>

using namespace swoole;

namespace swoole_test
{

static void init()
{
    /**
     * init eventloop
     */
    SwooleG.main_reactor = (swReactor *) sw_malloc(sizeof(swReactor));
    swReactor_create(SwooleG.main_reactor, SW_REACTOR_MAXEVENTS);
    swTimer_init(1);
}

static void coro1(void *arg)
{
    int cid = coroutine_get_cid();
    coroutine_t *co = coroutine_get_by_id(cid);
    printf("co yield\n");
    coroutine_yield(co);
    printf("co end\n");
}

int coroutine_create_test1()
{
    int cid = coroutine_create(coro1, NULL);
    if (cid < 0)
    {
        return -1;
    }
    printf("co resume, cid=%d\n", cid);
    coroutine_resume(coroutine_get_by_id(cid));
    return cid;
}

static void coro2(void *arg)
{
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.connect("127.0.0.1", 9801, 0.5);
    ASSERT_EQ(retval, false);
    ASSERT_EQ(sock.errCode, ECONNREFUSED);
}

void coroutine_socket_connect_refused()
{
    init();

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
    bool retval = sock.connect("192.0.0.1", 9801, 0.5);
    ASSERT_EQ(retval, false);
    ASSERT_EQ(sock.errCode, ETIMEDOUT);
}

void coroutine_socket_connect_timeout()
{
    init();

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

void coroutine_socket_connect_with_dns()
{
    init();
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

void coroutine_socket_recv_success()
{
    init();
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

void coroutine_socket_recv_fail()
{
    init();
    int cid = coroutine_create(coro6, NULL);
    if (cid < 0)
    {
        return;
    }
    SwooleG.main_reactor->wait(SwooleG.main_reactor, nullptr);
}

void coroutine_socket_bind_success()
{
    init();
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.bind("127.0.0.1", 9909);
    ASSERT_EQ(retval, true);
}

void coroutine_socket_bind_fail()
{
    init();
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.bind("192.111.11.1", 9909);
    ASSERT_EQ(retval, false);
    ASSERT_EQ(sock.errCode, EADDRNOTAVAIL);
}

void coroutine_socket_listen()
{
    init();
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

void coroutine_socket_accept()
{
    init();
    coroutine_create(coro7, NULL);
    coroutine_create(coro8, NULL);
    SwooleG.main_reactor->wait(SwooleG.main_reactor, nullptr);
}

//namespace end
}
