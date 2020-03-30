#include "tests.h"

TEST(reactor, swReactor_create)
{
    swReactor reactor;
    swReactor_create(&reactor, SW_REACTOR_MAXEVENTS);

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