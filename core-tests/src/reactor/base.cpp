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
#include "swoole_reactor.h"
#include "swoole_pipe.h"
#include "swoole_util.h"

using namespace std;
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

        ssize_t n = ev->socket->read(buffer, sizeof(buffer));
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

        ssize_t n = ev->socket->read(buffer, sizeof(buffer));
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

TEST(reactor, wait_timeout) {
    ASSERT_EQ(swoole_event_init(SW_EVENTLOOP_WAIT_EXIT), SW_OK);
    ASSERT_NE(SwooleTG.reactor, nullptr);

    sw_reactor()->set_timeout_msec(30);
    auto started_at = swoole::microtime();
    ASSERT_EQ(sw_reactor()->wait(), SW_OK);

    auto dr = swoole::microtime() - started_at;
    ASSERT_GE(dr, 0.03);
    ASSERT_LT(dr, 0.05);

    swoole_event_free();
}

TEST(reactor, wait_error) {
    ASSERT_EQ(swoole_event_init(SW_EVENTLOOP_WAIT_EXIT), SW_OK);
    ASSERT_NE(SwooleTG.reactor, nullptr);

    // ERROR: EINVAL epfd is not an epoll file descriptor, or maxevents is less than or equal to zero.
    sw_reactor()->max_event_num = 0;
    ASSERT_EQ(sw_reactor()->wait(), SW_ERR);
    ASSERT_EQ(errno, EINVAL);

    swoole_event_free();
}

TEST(reactor, writev) {
    network::Socket fake_sock{};

    UnixSocket p(true, SOCK_DGRAM);
    ASSERT_TRUE(p.ready());

    fake_sock.fd = p.get_socket(true)->get_fd();

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    struct iovec iov[2];

    iov[0].iov_base = (void *) "hello ";
    iov[0].iov_len = 6;

    iov[1].iov_base = (void *) "world\n";
    iov[1].iov_len = 6;

    ASSERT_EQ(swoole_event_writev(&fake_sock, iov, 2), 12);

    char buf[32];
    ASSERT_EQ(p.get_socket(false)->read(buf, sizeof(buf)), 12);
    ASSERT_MEMEQ("hello world\n", buf, 12);

    fake_sock.ssl = (SSL *) -1;
    ASSERT_EQ(swoole_event_writev(&fake_sock, iov, 2), -1);
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_OPERATION_NOT_SUPPORT);

    swoole_event_wait();
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
        ssize_t n = ev->socket->read(tg_buf->str + tg_buf->length, tg_buf->size - tg_buf->length);
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

    auto sock = p.get_socket(true);
    sock->buffer_size = 2 * 1024 * 1024;

    auto n = swoole_event_write(sock, str.value(), str.get_length());
    ASSERT_EQ(n, str.get_length());
    ASSERT_GT(sock->get_out_buffer_length(), 1024);

    std::cout << sock->get_out_buffer_length() << "\n";

    ASSERT_EQ(swoole_event_write(sock, str.value(), 256 * 1024), SW_ERR);
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_OUTPUT_BUFFER_OVERFLOW);

    ASSERT_EQ(swoole_event_write(sock, str.value(), sock->buffer_size + 8192), SW_ERR);
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_PACKAGE_LENGTH_TOO_LARGE);

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
    sock->move_fd();
    sock->free();
}

static const char *pkt = "hello world\r\n";

static void reactor_test_func(Reactor *reactor) {
    Pipe p(false);
    ASSERT_TRUE(p.ready());

    reactor->set_handler(SW_FD_PIPE | SW_EVENT_READ, [](Reactor *reactor, Event *event) -> int {
        char buf[1024];
        size_t l = strlen(pkt);
        size_t n = event->socket->read(buf, sizeof(buf));
        EXPECT_EQ(n, l);
        buf[n] = 0;
        EXPECT_EQ(std::string(buf, n), std::string(pkt));
        reactor->del(event->socket);

        return SW_OK;
    });

    reactor->set_handler(SW_FD_PIPE | SW_EVENT_WRITE, [](Reactor *reactor, Event *event) -> int {
        size_t l = strlen(pkt);
        EXPECT_EQ(event->socket->write(pkt, l), l);
        reactor->del(event->socket);

        return SW_OK;
    });

    ASSERT_EQ(reactor->add(p.get_socket(false), SW_EVENT_READ), SW_OK);
    ASSERT_EQ(reactor->add(p.get_socket(true), SW_EVENT_WRITE), SW_OK);

    UnixSocket unsock(false, SOCK_STREAM);
    ASSERT_TRUE(unsock.ready());

    int write_count = 0;
    auto sock2 = unsock.get_socket(false);
    sock2->object = &write_count;
    sock2->fd_type = SW_FD_STREAM;

    reactor->set_handler(SW_FD_STREAM | SW_EVENT_WRITE, [](Reactor *reactor, Event *event) -> int {
        int *count = (int *) event->socket->object;
        (*count)++;
        return SW_OK;
    });
    ASSERT_EQ(reactor->add(sock2, SW_FD_STREAM | SW_EVENT_WRITE | SW_EVENT_ONCE), SW_OK);

    ASSERT_EQ(write_count, 0);

    ASSERT_EQ(reactor->wait(), SW_OK);

    ASSERT_EQ(write_count, 1);
}

TEST(reactor, epoll) {
    Reactor reactor(1024, Reactor::TYPE_EPOLL);
    reactor.wait_exit = true;
    reactor_test_func(&reactor);
}

TEST(reactor, poll) {
    Reactor reactor(1024, Reactor::TYPE_POLL);
    reactor.wait_exit = true;
    reactor_test_func(&reactor);
}

TEST(reactor, poll_extra) {
    Reactor reactor(32, Reactor::TYPE_POLL);

    network::Socket fake_sock1{};
    fake_sock1.fd = 12345;

    network::Socket fake_sock2{};
    fake_sock2.fd = 99999;

    ASSERT_EQ(reactor.add(&fake_sock1, SW_EVENT_READ), SW_OK);
    ASSERT_EQ(reactor.add(&fake_sock2, SW_EVENT_READ), SW_OK);

    ASSERT_EQ(reactor.add(&fake_sock1, SW_EVENT_READ), SW_ERR);

    ASSERT_EQ(reactor.get_event_num(), 2);

    ASSERT_EQ(reactor.set(&fake_sock2, SW_EVENT_READ | SW_EVENT_WRITE | SW_EVENT_ERROR), SW_OK);

    ASSERT_EQ(reactor.del(&fake_sock2), SW_OK);
    ASSERT_EQ(reactor.get_event_num(), 1);

    network::Socket fake_sock3{};
    fake_sock3.fd = 88888;

    ASSERT_EQ(reactor.set(&fake_sock3, SW_EVENT_READ | SW_EVENT_WRITE), SW_ERR);
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_SOCKET_NOT_EXISTS);

    ASSERT_EQ(reactor.del(&fake_sock3), SW_ERR);
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_SOCKET_NOT_EXISTS);

    network::Socket fake_socks[32];
    SW_LOOP_N(32) {
        fake_socks[i].fd = i + 1024;
        if (i <= 30) {
            ASSERT_EQ(reactor.add(&fake_socks[i], SW_EVENT_READ), SW_OK);
        } else {
            ASSERT_EQ(reactor.add(&fake_socks[i], SW_EVENT_READ), SW_ERR);
        }
    }

    for (auto i = 31; i <= 0; i--) {
        fake_socks[i].fd = i + 1024;
        if (i <= 30) {
            ASSERT_EQ(reactor.del(&fake_socks[i]), SW_OK);
        } else {
            ASSERT_EQ(reactor.del(&fake_socks[i]), SW_ERR);
        }
    }
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

TEST(reactor, cycle) {
    Reactor reactor(1024, Reactor::TYPE_POLL);
    reactor.wait_exit = true;

    int event_loop_count = 0;
    const char *test = "hello world";

    reactor.future_task.callback = [&event_loop_count](void *data) {
        ASSERT_STREQ((char *) data, "hello world");
        event_loop_count++;
    };
    reactor.future_task.data = (void *) test;

    reactor_test_func(&reactor);

    ASSERT_GT(event_loop_count, 0);
}

static void event_idle_callback(void *data) {
    ASSERT_STREQ((char *) data, "hello world");
}

TEST(reactor, priority_idle_task) {
    Reactor reactor(1024, Reactor::TYPE_POLL);
    reactor.wait_exit = true;

    const char *test = "hello world";
    reactor.idle_task.callback = event_idle_callback;
    reactor.idle_task.data = (void *) test;
    reactor_test_func(&reactor);
}

TEST(reactor, hook) {
    Reactor *reactor = new Reactor(1024, Reactor::TYPE_POLL);
    reactor->wait_exit = true;

    swoole_add_hook(
        SW_GLOBAL_HOOK_ON_REACTOR_CREATE,
        [](void *data) -> void {
            Reactor *reactor = (Reactor *) data;
            ASSERT_EQ(Reactor::TYPE_POLL, reactor->type_);
        },
        1);

    swoole_add_hook(
        SW_GLOBAL_HOOK_ON_REACTOR_DESTROY,
        [](void *data) -> void {
            Reactor *reactor = (Reactor *) data;
            ASSERT_EQ(Reactor::TYPE_POLL, reactor->type_);
        },
        1);

    ON_SCOPE_EXIT {
        SwooleG.hooks[SW_GLOBAL_HOOK_ON_REACTOR_CREATE] = nullptr;
        SwooleG.hooks[SW_GLOBAL_HOOK_ON_REACTOR_DESTROY] = nullptr;
    };

    reactor_test_func(reactor);
    delete reactor;
}

TEST(reactor, set_fd) {
    UnixSocket p(true, SOCK_DGRAM);
    Reactor *reactor = new Reactor(1024, Reactor::TYPE_EPOLL);
    ASSERT_EQ(reactor->add(p.get_socket(false), SW_EVENT_READ), SW_OK);
    ASSERT_EQ(reactor->set(p.get_socket(false), SW_EVENT_WRITE), SW_OK);
    delete reactor;

    reactor = new Reactor(1024, Reactor::TYPE_POLL);
    ASSERT_EQ(reactor->add(p.get_socket(false), SW_EVENT_READ), SW_OK);
    ASSERT_EQ(reactor->set(p.get_socket(false), SW_EVENT_WRITE), SW_OK);
    delete reactor;
}

static void test_error_event(Reactor::Type type, int retval) {
    Pipe p(true);
    ASSERT_TRUE(p.ready());

    Reactor *reactor = new Reactor(1024, type);

    reactor->ptr = &retval;

    reactor->set_handler(SW_FD_PIPE | SW_EVENT_ERROR, [](Reactor *reactor, Event *event) -> int {
        EXPECT_EQ(reactor->del(event->socket), SW_OK);
        reactor->running = false;
        return *(int *) reactor->ptr;
    });

    reactor->add(p.get_socket(true), SW_EVENT_ERROR);
    reactor->add(p.get_socket(false), SW_EVENT_ERROR);

    p.close(SW_PIPE_CLOSE_WORKER);
    ASSERT_EQ(reactor->wait(), SW_OK);
    delete reactor;
}

TEST(reactor, error_event) {
    test_error_event(Reactor::TYPE_EPOLL, SW_OK);
    test_error_event(Reactor::TYPE_POLL, SW_OK);

    test_error_event(Reactor::TYPE_EPOLL, SW_ERR);
    test_error_event(Reactor::TYPE_POLL, SW_ERR);
}

TEST(reactor, error) {
    UnixSocket p(true, SOCK_DGRAM);

    swoole_set_print_backtrace_on_error(true);

    Reactor *reactor = new Reactor(1024, Reactor::TYPE_EPOLL);
    ASSERT_EQ(reactor->add(p.get_socket(false), SW_EVENT_READ), SW_OK);
    ASSERT_EQ(reactor->add(p.get_socket(false), SW_EVENT_WRITE), SW_ERR);
    ASSERT_EQ(errno, EEXIST);

    network::Socket bad_sock;
    bad_sock.removed = 1;
    bad_sock.fd_type = SW_FD_PIPE;
    bad_sock.fd = dup(p.get_socket(false)->get_fd());
    ASSERT_EQ(reactor->del(&bad_sock), SW_ERR);
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_EVENT_REMOVE_FAILED);

    ASSERT_EQ(reactor->add(&bad_sock, SW_EVENT_READ), SW_OK);
    close(bad_sock.fd);

    ASSERT_EQ(reactor->set(&bad_sock, SW_EVENT_READ | SW_EVENT_READ), SW_ERR);
    ASSERT_EQ(errno, EBADF);

    ASSERT_EQ(reactor->del(&bad_sock), SW_OK);

    delete reactor;

    reactor = new Reactor(1024, Reactor::TYPE_POLL);
    ASSERT_EQ(reactor->add(p.get_socket(false), SW_EVENT_READ), SW_OK);
    ASSERT_EQ(reactor->del(p.get_socket(false)), SW_OK);
    ASSERT_EQ(reactor->del(p.get_socket(false)), SW_ERR);
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_SOCKET_NOT_EXISTS);
    delete reactor;
}

TEST(reactor, drain_write_buffer) {
    int ret;
    UnixSocket p(true, SOCK_STREAM);
    ASSERT_TRUE(p.ready());

    ASSERT_EQ(swoole_event_init(SW_EVENTLOOP_WAIT_EXIT), SW_OK);

    p.set_blocking(false);
    p.set_buffer_size(65536);

    String str(DATA_SIZE);
    str.append_random_bytes(str.size - 1, false);
    str.append('\0');

    auto wsock = p.get_socket(true);

    auto n = swoole_event_write(wsock, str.value(), str.get_length());
    ASSERT_EQ(n, str.get_length());
    ASSERT_GT(wsock->get_out_buffer_length(), 1024);

    std::thread t([&]() {
        usleep(10000);
        auto rsock = p.get_socket(false);

        String rbuf(DATA_SIZE);
        while (true) {
            rsock->wait_event(1000, SW_EVENT_READ);
            auto n = rsock->read(rbuf.str + rbuf.length, rbuf.size - rbuf.length);
            if (n > 0) {
                rbuf.length += n;
                if (rbuf.length == rbuf.size) {
                    break;
                }
            }
        }

        ASSERT_MEMEQ(rbuf.str, str.str, DATA_SIZE);
    });

    sw_reactor()->drain_write_buffer(wsock);

    ret = swoole_event_wait();
    ASSERT_EQ(ret, SW_OK);
    ASSERT_FALSE(swoole_event_is_available());
    t.join();
}

TEST(reactor, handle_fail) {
    int ret;
    UnixSocket p(true, SOCK_DGRAM);
    ASSERT_TRUE(p.ready());

    ASSERT_EQ(swoole_event_init(SW_EVENTLOOP_WAIT_EXIT), SW_OK);
    ASSERT_NE(SwooleTG.reactor, nullptr);

    swoole_event_set_handler(SW_FD_PIPE | SW_EVENT_READ, [](Reactor *reactor, Event *ev) -> int {
        char buffer[16];

        ssize_t n = ev->socket->read(buffer, sizeof(buffer));
        EXPECT_EQ(strlen(pkt), n);
        EXPECT_MEMEQ(pkt, buffer, n);
        EXPECT_EQ(reactor->del(ev->socket), 0);

        EXPECT_EQ(reactor->get_event_num(), 0);

        return SW_ERR;
    });

    swoole_event_set_handler(SW_FD_PIPE | SW_EVENT_WRITE, [](Reactor *reactor, Event *ev) -> int {
        EXPECT_EQ(reactor->set(ev->socket, SW_EVENT_READ), 0);
        UnixSocket *p = (UnixSocket *) ev->socket->object;
        swoole_timer_after(10, [p](auto r1, auto r2) { p->get_socket(true)->write(pkt, strlen(pkt)); });
        return SW_ERR;
    });

    auto sock = p.get_socket(false);
    sock->object = &p;

    ret = swoole_event_add(sock, SW_EVENT_READ | SW_EVENT_WRITE);
    ASSERT_EQ(ret, SW_OK);

    ret = swoole_event_wait();
    ASSERT_EQ(ret, SW_OK);
    ASSERT_EQ(SwooleTG.reactor, nullptr);
}
