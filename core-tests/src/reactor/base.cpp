/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | @link     https://www.swoole.com/                                    |
  | @contact  team@swoole.com                                            |
  | @license  https://github.com/swoole/swoole-src/blob/master/LICENSE   |
  | @author   Tianfeng Han  <mikan.tenny@gmail.com>                      |
  +----------------------------------------------------------------------+
*/

#include "test_core.h"
#include "swoole_pipe.h"

using swoole::ReactorHandler;

TEST(reactor, create) {
    swoole_event_init(0);

    swReactor *reactor = SwooleTG.reactor;

    ASSERT_NE(reactor->object, nullptr);
    ASSERT_EQ(reactor->max_event_num, SW_REACTOR_MAXEVENTS);

    ASSERT_NE(reactor->add, nullptr);
    ASSERT_NE(reactor->set, nullptr);
    ASSERT_NE(reactor->del, nullptr);
    ASSERT_NE(reactor->wait, nullptr);
    ASSERT_NE(reactor->free, nullptr);

    ASSERT_TRUE(reactor->running);
    ASSERT_NE(reactor->write, nullptr);
    ASSERT_NE(reactor->close, nullptr);
    ASSERT_EQ(reactor->defer_tasks, nullptr);
    ASSERT_NE(reactor->default_write_handler, nullptr);

    /**
     * coroutine socket reactor
     */
    ASSERT_NE(reactor->read_handler[swReactor_fdtype(SW_FD_CORO_SOCKET | SW_EVENT_READ)], nullptr);
    ASSERT_NE(reactor->write_handler[swReactor_fdtype(SW_FD_CORO_SOCKET | SW_EVENT_WRITE)], nullptr);
    ASSERT_NE(reactor->error_handler[swReactor_fdtype(SW_FD_CORO_SOCKET | SW_EVENT_ERROR)], nullptr);

    /**
     * system reactor
     */
    ASSERT_NE(reactor->read_handler[swReactor_fdtype(SW_FD_CORO_POLL | SW_EVENT_READ)], nullptr);
    ASSERT_NE(reactor->write_handler[swReactor_fdtype(SW_FD_CORO_POLL | SW_EVENT_WRITE)], nullptr);
    ASSERT_NE(reactor->error_handler[swReactor_fdtype(SW_FD_CORO_POLL | SW_EVENT_ERROR)], nullptr);

    ASSERT_NE(reactor->read_handler[swReactor_fdtype(SW_FD_CORO_EVENT | SW_EVENT_READ)], nullptr);
    ASSERT_NE(reactor->write_handler[swReactor_fdtype(SW_FD_CORO_EVENT | SW_EVENT_WRITE)], nullptr);
    ASSERT_NE(reactor->error_handler[swReactor_fdtype(SW_FD_CORO_EVENT | SW_EVENT_ERROR)], nullptr);

    ASSERT_NE(reactor->read_handler[swReactor_fdtype(SW_FD_AIO | SW_EVENT_READ)], nullptr);

    swoole_event_free();
}

TEST(reactor, set_handler) {
    swReactor reactor;

    reactor.set_handler(SW_EVENT_READ, (ReactorHandler) 0x1);
    ASSERT_EQ(reactor.read_handler[swReactor_fdtype(SW_EVENT_READ)], (ReactorHandler) 0x1);

    reactor.set_handler(SW_EVENT_WRITE, (ReactorHandler) 0x2);
    ASSERT_EQ(reactor.write_handler[swReactor_fdtype(SW_EVENT_WRITE)], (ReactorHandler) 0x2);

    reactor.set_handler(SW_EVENT_ERROR, (ReactorHandler) 0x3);
    ASSERT_EQ(reactor.error_handler[swReactor_fdtype(SW_EVENT_ERROR)], (ReactorHandler) 0x3);
}

TEST(reactor, wait) {
    int ret;
    swPipe p;

    ret = swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
    ASSERT_EQ(ret, SW_OK);
    ASSERT_NE(SwooleTG.reactor, nullptr);

    ret = swPipeUnsock_create(&p, 1, SOCK_DGRAM);
    ASSERT_EQ(ret, SW_OK);

    swoole_event_set_handler(SW_FD_PIPE | SW_EVENT_READ, [](swReactor *reactor, swEvent *ev) -> int {
        char buffer[16];

        ssize_t n = read(ev->fd, buffer, sizeof(buffer));
        EXPECT_EQ(sizeof("hello world"), n);
        EXPECT_STREQ("hello world", buffer);
        reactor->del(reactor, ev->socket);

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

TEST(reactor, write) {
    int ret;
    swPipe p;

    ret = swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
    ASSERT_EQ(ret, SW_OK);
    ASSERT_NE(SwooleTG.reactor, nullptr);

    ret = swPipeUnsock_create(&p, 1, SOCK_DGRAM);
    ASSERT_EQ(ret, SW_OK);

    swoole_event_set_handler(SW_FD_PIPE | SW_EVENT_READ, [](swReactor *reactor, swEvent *ev) -> int {
        char buffer[16];

        ssize_t n = read(ev->fd, buffer, sizeof(buffer));
        EXPECT_EQ(sizeof("hello world"), n);
        EXPECT_STREQ("hello world", buffer);
        reactor->del(reactor, ev->socket);

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

static const char *pkt = "hello world\r\n";

static void reactor_test_func(swReactor *reactor) {
    swPipe p;
    ASSERT_EQ(swPipeBase_create(&p, 1), SW_OK);
    reactor->set_handler(SW_FD_PIPE | SW_EVENT_READ, [](swReactor *reactor, swEvent *event) -> int {
        char buf[1024];
        size_t l = strlen(pkt);
        size_t n = read(event->fd, buf, sizeof(buf));
        EXPECT_EQ(n, l);
        buf[n] = 0;
        EXPECT_EQ(std::string(buf, n), std::string(pkt));
        reactor->del(reactor, event->socket);

        return SW_OK;
    });
    reactor->set_handler(SW_FD_PIPE | SW_EVENT_WRITE, [](swReactor *reactor, swEvent *event) -> int {
        size_t l = strlen(pkt);
        EXPECT_EQ(write(event->fd, pkt, l), l);
        reactor->del(reactor, event->socket);

        return SW_OK;
    });
    reactor->add(reactor, p.get_socket(false), SW_EVENT_READ);
    reactor->add(reactor, p.get_socket(true), SW_EVENT_WRITE);
    reactor->wait(reactor, nullptr);

    p.close(&p);
}

TEST(reactor, poll) {
    swReactor reactor(1024);
    reactor.free(&reactor);
    reactor.wait_exit = true;
    ASSERT_EQ(swReactorPoll_create(&reactor, 1024), SW_OK);
    reactor_test_func(&reactor);
}

TEST(reactor, select) {
    swReactor reactor(1024);
    reactor.free(&reactor);
    reactor.wait_exit = true;
    ASSERT_EQ(swReactorSelect_create(&reactor), SW_OK);
    reactor_test_func(&reactor);
}
