#include "tests.h"

TEST(reactor, swReactor_create)
{
    swReactor reactor;

    int ret = swReactor_create(&reactor, SW_REACTOR_MAXEVENTS);
    ASSERT_EQ(ret, SW_OK);

    ASSERT_NE(reactor.object, nullptr);
    ASSERT_EQ(reactor.max_event_num, SW_REACTOR_MAXEVENTS);

    ASSERT_NE(reactor.add, nullptr);
    ASSERT_NE(reactor.set, nullptr);
    ASSERT_NE(reactor.del, nullptr);
    ASSERT_NE(reactor.wait, nullptr);
    ASSERT_NE(reactor.free, nullptr);

    ASSERT_EQ(reactor.running, 1);
    ASSERT_NE(reactor.onFinish, nullptr);
    ASSERT_NE(reactor.onTimeout, nullptr);
    ASSERT_NE(reactor.is_empty, nullptr);
    ASSERT_EQ(reactor.can_exit, nullptr); // set in PHP_METHOD(swoole_coroutine_scheduler, set)
    ASSERT_NE(reactor.write, nullptr);
    ASSERT_NE(reactor.close, nullptr);
    ASSERT_NE(reactor.defer, nullptr);
    ASSERT_EQ(reactor.defer_tasks, nullptr);
    ASSERT_NE(reactor.default_write_handler, nullptr);

    /**
     * coroutine socket reactor
     */
    ASSERT_NE(reactor.read_handler[swReactor_fdtype(SW_FD_CORO_SOCKET | SW_EVENT_READ)], nullptr);
    ASSERT_NE(reactor.write_handler[swReactor_fdtype(SW_FD_CORO_SOCKET | SW_EVENT_WRITE)], nullptr);
    ASSERT_NE(reactor.error_handler[swReactor_fdtype(SW_FD_CORO_SOCKET | SW_EVENT_ERROR)], nullptr);

    /**
     * system reactor
     */
    ASSERT_NE(reactor.read_handler[swReactor_fdtype(SW_FD_CORO_POLL | SW_EVENT_READ)], nullptr);
    ASSERT_NE(reactor.write_handler[swReactor_fdtype(SW_FD_CORO_POLL | SW_EVENT_WRITE)], nullptr);
    ASSERT_NE(reactor.error_handler[swReactor_fdtype(SW_FD_CORO_POLL | SW_EVENT_ERROR)], nullptr);

    ASSERT_NE(reactor.read_handler[swReactor_fdtype(SW_FD_CORO_EVENT | SW_EVENT_READ)], nullptr);
    ASSERT_NE(reactor.write_handler[swReactor_fdtype(SW_FD_CORO_EVENT | SW_EVENT_WRITE)], nullptr);
    ASSERT_NE(reactor.error_handler[swReactor_fdtype(SW_FD_CORO_EVENT | SW_EVENT_ERROR)], nullptr);

    ASSERT_NE(reactor.read_handler[swReactor_fdtype(SW_FD_AIO | SW_EVENT_READ)], nullptr);
}

TEST(reactor, swReactor_set_handler)
{
    swReactor reactor;

    swReactor_set_handler(&reactor, SW_EVENT_READ, (swReactor_handler) 0x1);
    ASSERT_EQ(reactor.read_handler[swReactor_fdtype(SW_EVENT_READ)], (swReactor_handler) 0x1);

    swReactor_set_handler(&reactor, SW_EVENT_WRITE, (swReactor_handler) 0x2);
    ASSERT_EQ(reactor.write_handler[swReactor_fdtype(SW_EVENT_WRITE)], (swReactor_handler) 0x2);

    swReactor_set_handler(&reactor, SW_EVENT_ERROR, (swReactor_handler) 0x3);
    ASSERT_EQ(reactor.error_handler[swReactor_fdtype(SW_EVENT_ERROR)], (swReactor_handler) 0x3);
}

TEST(reactor, swReactor_wait)
{
    int ret;
    swPipe p;

    ret = swoole_event_init();
    ASSERT_EQ(ret, SW_OK);
    ASSERT_NE(SwooleTG.reactor, nullptr);

    ret = swPipeUnsock_create(&p, 1, SOCK_DGRAM);
    ASSERT_EQ(ret, SW_OK);

    swoole_event_set_handler(SW_FD_PIPE | SW_EVENT_READ, [](swReactor *reactor, swEvent *ev) -> int
    {
        char buffer[16];

        ssize_t n = read(ev->fd, buffer, sizeof(buffer));
        EXPECT_EQ(sizeof("hello world"), n);
        EXPECT_STREQ("hello world", buffer);
        reactor->del(reactor, ev->socket);
        reactor->wait_exit = 1;

        return SW_OK;
    });

    ret = swoole_event_add(p.worker_socket, SW_EVENT_READ);
    ASSERT_EQ(ret, SW_OK);

    ret = p.write(&p, (void *) SW_STRS("hello world"));
    ASSERT_EQ(ret, sizeof("hello world"));

    ret = swoole_event_wait();
    ASSERT_EQ(ret, SW_OK);
    ASSERT_EQ(SwooleTG.reactor, nullptr);
}

TEST(reactor, swReactor_write)
{
    int ret;
    swPipe p;

    ret = swoole_event_init();
    ASSERT_EQ(ret, SW_OK);
    ASSERT_NE(SwooleTG.reactor, nullptr);

    ret = swPipeUnsock_create(&p, 1, SOCK_DGRAM);
    ASSERT_EQ(ret, SW_OK);

    swoole_event_set_handler(SW_FD_PIPE | SW_EVENT_READ, [](swReactor *reactor, swEvent *ev) -> int
    {
        char buffer[16];

        ssize_t n = read(ev->fd, buffer, sizeof(buffer));
        EXPECT_EQ(sizeof("hello world"), n);
        EXPECT_STREQ("hello world", buffer);
        reactor->del(reactor, ev->socket);
        reactor->wait_exit = 1;
        
        return SW_OK;
    });

    ret = swoole_event_add(p.worker_socket, SW_EVENT_READ);
    ASSERT_EQ(ret, SW_OK);

    ret = swoole_event_write(p.master_socket, (void *) SW_STRS("hello world"));
    ASSERT_EQ(ret, sizeof("hello world"));

    ret = swoole_event_wait();
    ASSERT_EQ(ret, SW_OK);
    ASSERT_EQ(SwooleTG.reactor, nullptr);
}
