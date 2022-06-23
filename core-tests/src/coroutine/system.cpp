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

#include "test_coroutine.h"
#include "swoole_pipe.h"

using namespace swoole;
using namespace swoole::test;

using swoole::coroutine::Socket;
using swoole::coroutine::System;

static const char *test_file = "/tmp/swoole-core-test";

static constexpr int DATA_SIZE = 8 * 1024 * 1024;
static constexpr int DATA_SIZE_2 = 64 * 1024;

TEST(coroutine_system, file) {
    test::coroutine::run([](void *arg) {
        std::shared_ptr<String> buf = std::make_shared<String>(DATA_SIZE);
        ASSERT_EQ(swoole_random_bytes(buf->str, buf->size - 1), buf->size - 1);
        buf->str[buf->size - 1] = 0;
        ASSERT_EQ(System::write_file(test_file, buf->str, buf->size, true, 0), buf->size);
        auto data = System::read_file(test_file, true);
        ASSERT_TRUE(data.get());
        ASSERT_STREQ(buf->str, data->str);
        unlink(test_file);
    });
}

TEST(coroutine_system, flock) {
    std::shared_ptr<String> buf = std::make_shared<String>(65536);
    ASSERT_EQ(swoole_random_bytes(buf->str, buf->size - 1), buf->size - 1);
    buf->str[buf->size - 1] = 0;

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    Coroutine::create([&buf](void *) {
        int fd = swoole_coroutine_open(test_file, File::WRITE | File::CREATE, 0666);
        ASSERT_TRUE(fd > 0);
        swoole_coroutine_flock_ex(test_file, fd, LOCK_EX);

        for (int i = 0; i < 4; i++) {
            Coroutine::create([&buf](void *) {
                int fd = swoole_coroutine_open(test_file, File::READ, 0);
                ASSERT_TRUE(fd > 0);
                swoole_coroutine_flock_ex(test_file, fd, LOCK_SH);
                String read_buf(DATA_SIZE_2);
                auto rn = swoole_coroutine_read(fd, read_buf.str, read_buf.size - 1);
                ASSERT_EQ(rn, read_buf.size - 1);
                read_buf.str[read_buf.size - 1] = 0;
                swoole_coroutine_flock_ex(test_file, fd, LOCK_UN);
                EXPECT_STREQ(read_buf.str, buf->str);
                swoole_coroutine_close(fd);
            });
        }

        auto wn = swoole_coroutine_write(fd, buf->str, buf->size - 1);
        ASSERT_EQ(wn, buf->size - 1);
        swoole_coroutine_flock_ex(test_file, fd, LOCK_UN);
        swoole_coroutine_close(fd);
    });

    swoole_event_wait();
    unlink(test_file);
}

TEST(coroutine_system, flock_nb) {
    coroutine::run([&](void *arg) {
        int fd = swoole_coroutine_open(test_file, File::WRITE | File::CREATE, 0666);
        ASSERT_EQ(swoole_coroutine_flock_ex(test_file, fd, LOCK_EX | LOCK_NB), 0);

        swoole::Coroutine::create([&](void *arg) {
            ASSERT_EQ(swoole_coroutine_flock_ex(test_file, fd, LOCK_EX), 0);
            ASSERT_EQ(swoole_coroutine_flock_ex(test_file, fd, LOCK_UN), 0);
            swoole_coroutine_close(fd);
            unlink(test_file);
        });

        ASSERT_EQ(swoole_coroutine_flock_ex(test_file, fd, LOCK_UN), 0);
    });
}

TEST(coroutine_system, cancel_sleep) {
    test::coroutine::run([](void *arg) {
        auto co = Coroutine::get_current_safe();
        Coroutine::create([co](void *) {
            System::sleep(0.002);
            co->cancel();
        });
        System::sleep(1000);
    });
}

TEST(coroutine_system, getaddrinfo) {
    test::coroutine::run([](void *arg) {
        std::vector<std::string> ip_list = System::getaddrinfo("www.baidu.com", AF_INET, SOCK_STREAM, 0, "http", 1);
        ASSERT_GT(ip_list.size(), 0);
        for (auto &ip : ip_list) {
            ASSERT_TRUE(swoole::network::Address::verify_ip(AF_INET, ip));
        }
    });
}

TEST(coroutine_system, wait_signal) {
    test::coroutine::run([](void *arg) {
        Coroutine::create([](void *) {
            System::sleep(0.002);
            kill(getpid(), SIGUSR1);
        });
        ASSERT_TRUE(System::wait_signal(SIGUSR1, 1.0));
        ASSERT_FALSE(System::wait_signal(SIGUSR2, 0.1));
    });
}

static const char *GREETING = "hello world, hello swoole";

TEST(coroutine_system, wait_event_readable) {
    UnixSocket p(true, SOCK_DGRAM);
    ASSERT_TRUE(p.ready());

    test::coroutine::run([&p](void *arg) {
        Coroutine::create([&p](void *) {
            System::sleep(0.002);
            ASSERT_GT(p.write(GREETING, strlen(GREETING)), 0);
        });

        char buffer[128];
        auto pipe_sock = p.get_socket(false);
        System::wait_event(pipe_sock->get_fd(), SW_EVENT_READ, 1);
        ssize_t n = pipe_sock->read(buffer, sizeof(buffer));
        buffer[n] = 0;
        EXPECT_EQ(strlen(GREETING), n);
        EXPECT_STREQ(GREETING, buffer);
    });
}

TEST(coroutine_system, wait_event_writable) {
    UnixSocket p(true, SOCK_STREAM);
    ASSERT_TRUE(p.ready());
    p.set_blocking(false);
    p.set_buffer_size(65536);
    sw_tg_buffer()->clear();

    String str(2 * SW_NUM_MILLION);
    str.append_random_bytes(str.size - 1, false);
    str.append('\0');

    test::coroutine::run([&](void *arg) {
        Coroutine::create([&](void *) {
            System::sleep(0.002);
            auto pipe_sock = p.get_socket(true);

            char *ptr = str.value();
            size_t len = str.get_length();

            while (len > 0) {
                ssize_t retval = pipe_sock->write(ptr, len > 8192 ? 8192 : len);
                if (retval > 0) {
                    ptr += retval;
                    len -= retval;
                } else if (retval == 0 || (retval < 0 && errno != EAGAIN)) {
                    break;
                }
                System::wait_event(pipe_sock->get_fd(), SW_EVENT_WRITE, 1);
            }
        });

        auto pipe_sock = p.get_socket(false);
        auto tg_buf = sw_tg_buffer();

        while (tg_buf->length < str.size - 1) {
            ssize_t retval = pipe_sock->read(tg_buf->str + tg_buf->length, tg_buf->size - tg_buf->length);
            if (retval > 0) {
                tg_buf->grow(retval);
                continue;
            } else if (retval == 0 && (retval < 0 && errno != EAGAIN)) {
                break;
            }
            System::wait_event(pipe_sock->get_fd(), SW_EVENT_READ, 1);
        }
        tg_buf->append('\0');
        EXPECT_STREQ(sw_tg_buffer()->value(), str.value());
    });
}

TEST(coroutine_system, swoole_stream_select) {
    UnixSocket p(true, SOCK_STREAM);
    std::unordered_map<int, swoole::coroutine::PollSocket> fds;
    fds.emplace(std::make_pair(p.get_socket(false)->fd, swoole::coroutine::PollSocket(SW_EVENT_READ, nullptr)));

    test::coroutine::run([&](void *arg) {
        // try timeout to trigger socket_poll_timeout function
        ASSERT_FALSE(System::socket_poll(fds, 0.5));
    });

    // start normal process
    test::coroutine::run([&](void *arg) {
        std::string text = "Hello world";
        size_t len = text.length();

        // child pipe
        Coroutine::create([&](void *) {
            System::sleep(0.05);
            auto pipe_sock = p.get_socket(true);
            const char *ptr = text.c_str();
            ASSERT_EQ(pipe_sock->write(ptr, len), len);
        });

        // master pipe
        bool result = System::socket_poll(fds, 0.5);
        ASSERT_TRUE(result);

        char buffer[128];
        auto pipe_sock = p.get_socket(false);
        ssize_t retval = pipe_sock->read(buffer, sizeof(buffer));
        buffer[retval] = '\0';

        ASSERT_EQ(retval, len);
        const char *ptr = text.c_str();
        ASSERT_STREQ(ptr, buffer);
    });
}

TEST(coroutine_system, timeout_is_zero) {
    UnixSocket p(true, SOCK_STREAM);
    std::unordered_map<int, swoole::coroutine::PollSocket> fds;
    fds.emplace(std::make_pair(p.get_socket(false)->fd, swoole::coroutine::PollSocket(SW_EVENT_READ, nullptr)));

    // timeout is 0
    test::coroutine::run([&](void *arg) {
        std::string text = "Hello world";
        size_t len = text.length();

        // child pipe
        Coroutine::create([&](void *) {
            auto pipe_sock = p.get_socket(true);
            const char *ptr = text.c_str();
            ASSERT_EQ(pipe_sock->write(ptr, len), len);
        });

        // master pipe
        bool result = System::socket_poll(fds, 0);
        ASSERT_TRUE(result);

        // child pipe
        Coroutine::create([&](void *) {
            auto pipe_sock = p.get_socket(true);
            const char *ptr = text.c_str();
            ASSERT_EQ(pipe_sock->write(ptr, len), len);
        });

        // master pipe
        auto pipe_sock = p.get_socket(false);
        result = System::wait_event(pipe_sock->get_fd(), SW_EVENT_READ, 0);
        ASSERT_TRUE(result);
    });
}
