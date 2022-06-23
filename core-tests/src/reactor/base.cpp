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
  | @Author   Tianfeng Han  <rango@swoole.com>                           |
  +----------------------------------------------------------------------+
*/

#include "test_core.h"
#include "swoole_pipe.h"

using namespace swoole;

TEST(reactor, create) {
    swoole_event_init(0);

    Reactor *reactor = SwooleTG.reactor;

    ASSERT_EQ(reactor->max_event_num, SW_REACTOR_MAXEVENTS);

    ASSERT_TRUE(reactor->running);
    ASSERT_NE(reactor->write, nullptr);
    ASSERT_NE(reactor->close, nullptr);
    ASSERT_EQ(reactor->defer_tasks, nullptr);
    ASSERT_NE(reactor->default_write_handler, nullptr);

    /**
     * coroutine socket reactor
     */
    ASSERT_NE(reactor->read_handler[Reactor::get_fd_type(SW_FD_CO_SOCKET | SW_EVENT_READ)], nullptr);
    ASSERT_NE(reactor->write_handler[Reactor::get_fd_type(SW_FD_CO_SOCKET | SW_EVENT_WRITE)], nullptr);
    ASSERT_NE(reactor->error_handler[Reactor::get_fd_type(SW_FD_CO_SOCKET | SW_EVENT_ERROR)], nullptr);

    /**
     * system reactor
     */
    ASSERT_NE(reactor->read_handler[Reactor::get_fd_type(SW_FD_CO_POLL | SW_EVENT_READ)], nullptr);
    ASSERT_NE(reactor->write_handler[Reactor::get_fd_type(SW_FD_CO_POLL | SW_EVENT_WRITE)], nullptr);
    ASSERT_NE(reactor->error_handler[Reactor::get_fd_type(SW_FD_CO_POLL | SW_EVENT_ERROR)], nullptr);

    ASSERT_NE(reactor->read_handler[Reactor::get_fd_type(SW_FD_CO_EVENT | SW_EVENT_READ)], nullptr);
    ASSERT_NE(reactor->write_handler[Reactor::get_fd_type(SW_FD_CO_EVENT | SW_EVENT_WRITE)], nullptr);
    ASSERT_NE(reactor->error_handler[Reactor::get_fd_type(SW_FD_CO_EVENT | SW_EVENT_ERROR)], nullptr);

    ASSERT_NE(reactor->read_handler[Reactor::get_fd_type(SW_FD_AIO | SW_EVENT_READ)], nullptr);

    swoole_event_free();
}

TEST(reactor, set_handler) {
    Reactor reactor;

    reactor.set_handler(SW_EVENT_READ, (ReactorHandler) 0x1);
    ASSERT_EQ(reactor.read_handler[Reactor::get_fd_type(SW_EVENT_READ)], (ReactorHandler) 0x1);

    reactor.set_handler(SW_EVENT_WRITE, (ReactorHandler) 0x2);
    ASSERT_EQ(reactor.write_handler[Reactor::get_fd_type(SW_EVENT_WRITE)], (ReactorHandler) 0x2);

    reactor.set_handler(SW_EVENT_ERROR, (ReactorHandler) 0x3);
    ASSERT_EQ(reactor.error_handler[Reactor::get_fd_type(SW_EVENT_ERROR)], (ReactorHandler) 0x3);
}

TEST(reactor, wait) {
    int ret;
    UnixSocket p(true, SOCK_DGRAM);
    ASSERT_TRUE(p.ready());

    ret = swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
    ASSERT_EQ(ret, SW_OK);
    ASSERT_NE(SwooleTG.reactor, nullptr);

    swoole_event_set_handler(SW_FD_PIPE | SW_EVENT_READ, [](Reactor *reactor, Event *ev) -> int {
        char buffer[16];

        ssize_t n = read(ev->fd, buffer, sizeof(buffer));
        EXPECT_EQ(sizeof("hello world"), n);
        EXPECT_STREQ("hello world", buffer);
        reactor->del(ev->socket);

        return SW_OK;
    });

    ret = swoole_event_add(p.get_socket(false), SW_EVENT_READ);
    ASSERT_EQ(swoole_event_get_socket(p.get_socket(false)->get_fd()), p.get_socket(false));
    ASSERT_EQ(ret, SW_OK);

    ret = p.write((void *) SW_STRS("hello world"));
    ASSERT_EQ(ret, sizeof("hello world"));

    ret = swoole_event_wait();
    ASSERT_EQ(ret, SW_OK);
    ASSERT_EQ(SwooleTG.reactor, nullptr);
}

TEST(reactor, write) {
    int ret;
    UnixSocket p(true, SOCK_DGRAM);
    ASSERT_TRUE(p.ready());
    p.set_blocking(false);
    p.set_buffer_size(65536);

    ret = swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
    ASSERT_EQ(ret, SW_OK);
    ASSERT_NE(SwooleTG.reactor, nullptr);

    swoole_event_set_handler(SW_FD_PIPE | SW_EVENT_READ, [](Reactor *reactor, Event *ev) -> int {
        char buffer[16];

        ssize_t n = read(ev->fd, buffer, sizeof(buffer));
        EXPECT_EQ(sizeof("hello world"), n);
        EXPECT_STREQ("hello world", buffer);
        reactor->del(ev->socket);

        return SW_OK;
    });

    ret = swoole_event_add(p.get_socket(false), SW_EVENT_READ);
    ASSERT_EQ(ret, SW_OK);

    auto sock = p.get_socket(true);

    auto n = swoole_event_write(sock, (void *) SW_STRS("hello world"));
    ASSERT_EQ(n, sizeof("hello world"));

    ret = swoole_event_wait();
    ASSERT_EQ(ret, SW_OK);
    ASSERT_EQ(SwooleTG.reactor, nullptr);
}

constexpr int DATA_SIZE = 2 * SW_NUM_MILLION;

TEST(reactor, write_2m) {
    int ret;
    UnixSocket p(true, SOCK_STREAM);
    ASSERT_TRUE(p.ready());

    ret = swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
    ASSERT_EQ(ret, SW_OK);
    ASSERT_NE(SwooleTG.reactor, nullptr);

    swoole_event_set_handler(SW_FD_PIPE | SW_EVENT_READ, [](Reactor *reactor, Event *ev) -> int {
        auto tg_buf = sw_tg_buffer();
        ssize_t n = read(ev->fd, tg_buf->str + tg_buf->length, tg_buf->size - tg_buf->length);
        if (n <= 0) {
            return SW_ERR;
        }
        tg_buf->grow(n);
        if (tg_buf->length == DATA_SIZE) {
            tg_buf->append('\0');
            reactor->del(ev->socket);
        }
        return SW_OK;
    });

    p.set_blocking(false);
    p.set_buffer_size(65536);

    ret = swoole_event_add(p.get_socket(false), SW_EVENT_READ);
    ASSERT_EQ(ret, SW_OK);

    String str(DATA_SIZE);
    str.append_random_bytes(str.size - 1, false);
    str.append('\0');

    sw_tg_buffer()->clear();

    auto n = swoole_event_write(p.get_socket(true), str.value(), str.get_length());
    ASSERT_EQ(n, str.get_length());
    ASSERT_GT(p.get_socket(true)->out_buffer->length(), 1024);

    ret = swoole_event_wait();
    ASSERT_EQ(ret, SW_OK);
    ASSERT_FALSE(swoole_event_is_available());
    ASSERT_STREQ(sw_tg_buffer()->value(), str.value());
}

TEST(reactor, bad_fd) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
    auto sock = make_socket(999999, SW_FD_STREAM_CLIENT);
    sock->nonblock = 1;
    auto n = swoole_event_write(sock, SW_STRL("hello world"));
    ASSERT_EQ(n, SW_ERR);
    ASSERT_EQ(swoole_get_last_error(), EBADF);
    swoole_event_free();
    sock->fd = -1;
    sock->free();
}

static const char *pkt = "hello world\r\n";

static void reactor_test_func(Reactor *reactor) {
    Pipe p(true);
    ASSERT_TRUE(p.ready());

    reactor->set_handler(SW_FD_PIPE | SW_EVENT_READ, [](Reactor *reactor, Event *event) -> int {
        char buf[1024];
        size_t l = strlen(pkt);
        size_t n = read(event->fd, buf, sizeof(buf));
        EXPECT_EQ(n, l);
        buf[n] = 0;
        EXPECT_EQ(std::string(buf, n), std::string(pkt));
        reactor->del(event->socket);

        return SW_OK;
    });
    reactor->set_handler(SW_FD_PIPE | SW_EVENT_WRITE, [](Reactor *reactor, Event *event) -> int {
        size_t l = strlen(pkt);
        EXPECT_EQ(write(event->fd, pkt, l), l);
        reactor->del(event->socket);

        return SW_OK;
    });
    reactor->add(p.get_socket(false), SW_EVENT_READ);
    reactor->add(p.get_socket(true), SW_EVENT_WRITE);
    reactor->wait(nullptr);
}

TEST(reactor, poll) {
    Reactor reactor(1024, Reactor::TYPE_POLL);
    reactor.wait_exit = true;
    reactor_test_func(&reactor);
}

TEST(reactor, select) {
    Reactor reactor(1024, Reactor::TYPE_SELECT);
    reactor.wait_exit = true;
    reactor_test_func(&reactor);
}

TEST(reactor, add_or_update) {
    int ret;
    UnixSocket p(true, SOCK_DGRAM);
    ASSERT_TRUE(p.ready());

    ret = swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
    ASSERT_EQ(ret, SW_OK);
    ASSERT_NE(SwooleTG.reactor, nullptr);

    ret = swoole_event_add_or_update(p.get_socket(false), SW_EVENT_READ);
    ASSERT_EQ(ret, SW_OK);
    ASSERT_TRUE(p.get_socket(false)->events & SW_EVENT_READ);

    ret = swoole_event_add_or_update(p.get_socket(false), SW_EVENT_WRITE);
    ASSERT_EQ(ret, SW_OK);
    ASSERT_TRUE(p.get_socket(false)->events & SW_EVENT_READ);
    ASSERT_TRUE(p.get_socket(false)->events & SW_EVENT_WRITE);

    swoole_event_free();
}

TEST(reactor, defer_task) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
    Reactor *reactor = sw_reactor();
    ASSERT_EQ(reactor->max_event_num, SW_REACTOR_MAXEVENTS);

    int count = 0;
    reactor->defer([&count](void *) { count++; });
    swoole_event_wait();
    ASSERT_EQ(count, 1);
    swoole_event_free();
}
