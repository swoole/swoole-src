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
  | Author: NathanFreeman  <mariasocute@163.com>                         |
  +----------------------------------------------------------------------+
 */

#include "test_coroutine.h"
#include "swoole_iouring.h"

#include <sys/file.h>
#include <sys/stat.h>

#ifdef SW_USE_IOURING
using swoole::Iouring;
using swoole::Reactor;
using swoole::coroutine::System;
using swoole::test::coroutine;
using swoole::test::create_socket_pair;

TEST(iouring, create) {
    coroutine::run([](void *arg) {
        SwooleG.iouring_entries = 4;
        SwooleG.iouring_workers = 65536;
        auto fd = Iouring::open(TEST_TMP_FILE, O_CREAT, 0666);
        ASSERT_GE(fd, 0);
        ASSERT_NE(Iouring::close(fd), -1);
    });
}

TEST(iouring, list_all_opcode) {
    auto list = Iouring::list_all_opcode();
    for (auto &item : list) {
        DEBUG() << "opcode: " << item.first << ", value: " << item.second << "\n";
    }
    ASSERT_TRUE(list.size() > 0);
}

TEST(iouring, open_and_close) {
    coroutine::run([](void *arg) {
        const char *test_file = "/tmp/file_1";
        int fd = Iouring::open(test_file, O_CREAT, 0666);
        ASSERT_TRUE(fd > 0);

        int result = Iouring::close(fd);
        ASSERT_TRUE(result == 0);

        result = Iouring::unlink(test_file);
        ASSERT_TRUE(result == 0);
    });
}

TEST(iouring, mkdir_and_rmdir) {
    coroutine::run([](void *arg) {
        const char *directory = "/tmp/aaaa";
        int rv;

        rv = Iouring::mkdir(directory, 0755);
        ASSERT_EQ(rv, 0);

        rv = Iouring::rmdir(directory);
        ASSERT_EQ(rv, 0);
    });
}

TEST(iouring, write_and_read) {
    coroutine::run([](void *arg) {
        const char *test_file = "/tmp/file_2";
        int fd = Iouring::open(test_file, O_CREAT | O_RDWR, 0666);
        ASSERT_TRUE(fd > 0);

        const char *data = "aaaaaaaaaaaaaaaaaaaaaaa";
        size_t length = strlen(data);
        ssize_t result = Iouring::write(fd, (const void *) data, length);
        ASSERT_TRUE(result > 0);
        ASSERT_TRUE(result == static_cast<ssize_t>(length));

        lseek(fd, 0, SEEK_SET);

        char buf[128];
        result = Iouring::read(fd, (void *) buf, 128);
        ASSERT_TRUE(result > 0);
        ASSERT_TRUE(result == static_cast<ssize_t>(length));
        buf[result] = '\0';
        ASSERT_STREQ(data, buf);

        result = Iouring::close(fd);
        ASSERT_TRUE(result == 0);

        result = Iouring::unlink(test_file);
        ASSERT_TRUE(result == 0);
    });
}

TEST(iouring, rename) {
    coroutine::run([](void *arg) {
        const char *oldpath = "/tmp/file_2";
        const char *newpath = "/tmp/file_3";
        int fd = Iouring::open(oldpath, O_CREAT | O_RDWR, 0666);
        ASSERT_TRUE(fd > 0);

        int result = Iouring::close(fd);
        ASSERT_TRUE(result == 0);

        result = Iouring::rename(oldpath, newpath);
        ASSERT_TRUE(result == 0);

        result = Iouring::unlink(newpath);
        ASSERT_TRUE(result == 0);
    });
}

#ifdef HAVE_IOURING_STATX
TEST(iouring, fstat_and_stat) {
    coroutine::run([](void *arg) {
        struct stat statbuf {};
        int fd = Iouring::open(TEST_TMP_FILE, O_CREAT | O_RDWR, 0666);
        ASSERT_TRUE(fd > 0);

        ASSERT_EQ(Iouring::write(fd, TEST_STR, strlen(TEST_STR)), strlen(TEST_STR));

        int result = Iouring::fstat(fd, &statbuf);
        ASSERT_TRUE(result == 0);
        ASSERT_TRUE(statbuf.st_size > 0);

        result = Iouring::close(fd);
        ASSERT_TRUE(result == 0);

        statbuf = {};
        result = Iouring::stat(TEST_TMP_FILE, &statbuf);
        ASSERT_TRUE(result == 0);
        ASSERT_TRUE(statbuf.st_size > 0);
    });
}
#endif

TEST(iouring, fsync_and_fdatasync) {
    coroutine::run([](void *arg) {
        const char *test_file = "/tmp/file_2";
        int fd = Iouring::open(test_file, O_CREAT | O_RDWR, 0666);
        ASSERT_TRUE(fd > 0);

        const char *data = "aaaaaaaaaaaaaaaaaaaaaaa";
        size_t length = strlen(data);
        ssize_t write_length = Iouring::write(fd, (const void *) data, length);
        ASSERT_TRUE(write_length == static_cast<ssize_t>(length));

        int result = Iouring::fsync(fd);
        ASSERT_TRUE(result == 0);

        write_length = Iouring::write(fd, (const void *) data, length);
        ASSERT_TRUE(write_length == static_cast<ssize_t>(length));

        result = Iouring::fdatasync(fd);
        ASSERT_TRUE(result == 0);

        result = Iouring::close(fd);
        ASSERT_TRUE(result == 0);

        result = Iouring::unlink(test_file);
        ASSERT_TRUE(result == 0);
    });
}

#ifdef HAVE_IOURING_FTRUNCATE
TEST(iouring, ftruncate) {
    coroutine::run([&](void *arg) {
        const char *test_file = "/tmp/file_3";
        int fd = Iouring::open(test_file, O_CREAT | O_RDWR, 0666);
        ASSERT_TRUE(fd > 0);

        const char *data = "aaaaaaaaaaaaaaaaaaaaaaa";
        size_t length = strlen(data);
        ssize_t write_length = Iouring::write(fd, (const void *) data, length);
        ASSERT_TRUE(write_length == static_cast<ssize_t>(length));

        int result = Iouring::ftruncate(fd, 0);
        ASSERT_TRUE(result == 0);
        Iouring::close(fd);
    });
}
#endif
#endif

TEST(iouring, connect) {
    signal(SIGPIPE, SIG_IGN);
    coroutine::run([](void *arg) {
        int fd = Iouring::socket(AF_INET, SOCK_STREAM, 0);
        ASSERT_NE(fd, -1);

        swoole::network::Address addr{};
        ASSERT_TRUE(addr.assign(SW_SOCK_TCP, "www.baidu.com", 80, true));

        int rv = Iouring::connect(fd, &addr.addr.ss, addr.len);

        rv = Iouring::write(fd, TEST_REQUEST_BAIDU, strlen(TEST_REQUEST_BAIDU));
        ASSERT_EQ(rv, strlen(TEST_REQUEST_BAIDU));

        char buf[4096];

        rv = Iouring::read(fd, buf, sizeof(buf));
        ASSERT_GT(rv, 100);

        std::string s{buf};
        ASSERT_TRUE(s.find("Location: https://www.baidu.com/") != s.npos);

        Iouring::close(fd);
    });
}

TEST(iouring, send_recv) {
    signal(SIGPIPE, SIG_IGN);
    coroutine::run([](void *arg) {
        int fd = Iouring::socket(AF_INET, SOCK_STREAM, 0);
        ASSERT_NE(fd, -1);

        swoole::network::Address addr{};
        ASSERT_TRUE(addr.assign(SW_SOCK_TCP, "www.baidu.com", 80, true));

        int rv = Iouring::connect(fd, &addr.addr.ss, addr.len);

        rv = Iouring::send(fd, TEST_REQUEST_BAIDU, strlen(TEST_REQUEST_BAIDU), 0);
        ASSERT_EQ(rv, strlen(TEST_REQUEST_BAIDU));

        char buf[4096];

        rv = Iouring::recv(fd, buf, sizeof(buf), 0);
        ASSERT_GT(rv, 100);

        std::string s{buf};
        ASSERT_TRUE(s.find("Location: https://www.baidu.com/") != s.npos);

        Iouring::close(fd);
    });
}

TEST(iouring, accept) {
    coroutine::run([](void *arg) {
        // Create a TCP socket using coroutine API
        int server_sock = Iouring::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        ASSERT_GT(server_sock, 0);

        // Bind the socket to localhost with port 0 (auto-assign)
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        server_addr.sin_port = 0;

        int retval = Iouring::bind(server_sock, (struct sockaddr *) &server_addr, sizeof(server_addr));
        ASSERT_EQ(retval, 0);

        // Listen on the socket
        retval = Iouring::listen(server_sock, 128);
        ASSERT_EQ(retval, 0);

        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        // Test that swoole_coroutine_accept works correctly
        Coroutine::create([&](void *arg) {
            // Give the server time to start listening
            System::sleep(0.01);

            // Connect to the server using coroutine API
            int client_sock = Iouring::socket(AF_INET, SOCK_STREAM, 0);
            ASSERT_GT(client_sock, 0);

            // Get the actual server port
            struct sockaddr_in actual_server_addr;
            socklen_t addr_len = sizeof(actual_server_addr);
            ASSERT_EQ(getsockname(server_sock, (struct sockaddr *) &actual_server_addr, &addr_len), 0);

            // Connect to the server
            retval = Iouring::connect(client_sock, (struct sockaddr *) &actual_server_addr, addr_len);
            ASSERT_EQ(retval, 0);

            // Send a test message
            const char *test_message = "test_data";
            ssize_t sent_bytes = Iouring::send(client_sock, test_message, strlen(test_message), 0);
            ASSERT_EQ(sent_bytes, (ssize_t) strlen(test_message));

            // Close the client socket
            Iouring::close(client_sock);
        });

        // Accept the connection using coroutine API
        int client_sock = Iouring::accept(server_sock, (struct sockaddr *) &client_addr, &client_addr_len);
        ASSERT_GT(client_sock, 0);

        // Receive data from client
        char buffer[256] = {};
        ssize_t received_bytes = Iouring::recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        ASSERT_GT(received_bytes, 0);
        ASSERT_STREQ(buffer, "test_data");

        // Close the client socket
        Iouring::close(client_sock);
        Iouring::close(server_sock);
    });
}

TEST(iouring, sleep) {
    coroutine::run([](void *arg) {
        {
            auto begin = swoole::microtime();
            Iouring::sleep(1, 200 * SW_NUM_MILLION);
            auto end = swoole::microtime();
            ASSERT_GE(end - begin, 1.2);
        }

        {
            auto begin = swoole::microtime();
            Iouring::sleep(0, 300 * SW_NUM_MILLION);
            auto end = swoole::microtime();
            ASSERT_GE(end - begin, 0.3);
        }
    });
}

TEST(iouring, wait_success) {
    auto pid = swoole::test::spawn_exec([]() { sleep(1); });

    coroutine::run([pid](void *arg) {
        int status;
        ASSERT_EQ(Iouring::wait(&status, 5), pid);
        ASSERT_EQ(status, 0);
    });
}

TEST(iouring, wait_timeout) {
    auto pid = swoole::test::spawn_exec([]() { sleep(2000); });

    coroutine::run([pid](void *arg) {
        int status = 0x9501;
        ASSERT_EQ(Iouring::wait(&status, 0.5), -1);
        ASSERT_EQ(errno, ETIMEDOUT);
        ASSERT_EQ(status, 0x9501);  // After the timeout, the status will not be set.
    });

    kill(pid, SIGKILL);
}

TEST(iouring, waitpid) {
    auto pid = swoole::test::spawn_exec([]() { sleep(2000); });

    coroutine::run([pid](void *arg) {
        int status;
        ASSERT_EQ(Iouring::waitpid(pid, &status, WNOHANG, -1), 0);
        ASSERT_EQ(Iouring::waitpid(pid, &status, 0, 0.1), -1);
        ASSERT_EQ(errno, ETIMEDOUT);

        kill(pid, SIGKILL);
        System::sleep(0.3);
        ASSERT_EQ(Iouring::waitpid(pid, &status, 0, 0.1), pid);
    });
}

TEST(iouring, poll) {
    auto buffer = sw_tg_buffer();
    buffer->clear();
    buffer->append_random_bytes(256 * 1024, false);

    coroutine::run([=](void *arg) {
        int pair[2];
        struct pollfd fds[2];
        char buf[4096];
        socketpair(AF_UNIX, SOCK_STREAM, 0, pair);

        std::map<std::string, bool> results;
        auto _fd0 = pair[0];
        auto _fd1 = pair[1];

        bzero(fds, sizeof(pollfd));
        fds[0].fd = _fd0;
        fds[0].events = POLLIN | POLLOUT;
        ASSERT_EQ(Iouring::poll(fds, 1, 1000), 1);
        ASSERT_TRUE(fds[0].revents & POLLOUT);

        Coroutine::create([=](void *) {
            ssize_t result;
            result = Iouring::write(_fd0, buffer->value(), buffer->get_length());
            ASSERT_GT(result, 0);
            Iouring::sleep(0.1);
            result = Iouring::write(_fd1, buffer->value(), 16 * 1024);
            ASSERT_GT(result, 0);
        });

        bzero(fds, sizeof(pollfd));
        fds[0].fd = _fd1;
        fds[0].events = POLLIN;

        ASSERT_EQ(Iouring::poll(fds, 1, 1000), 1);
        ASSERT_TRUE(fds[0].revents & POLLIN);

        ssize_t result = Iouring::read(_fd1, buf, sizeof(buf));
        ASSERT_GT(result, 1024);

        bzero(fds, sizeof(pollfd));
        ASSERT_EQ(Iouring::poll(fds, 2, 1000), -1);
        ASSERT_EQ(swoole_get_last_error(), SW_ERROR_INVALID_PARAMS);

        System::sleep(0.02);

        bzero(fds, sizeof(pollfd));
        fds[0].fd = _fd0;
        fds[0].events = POLLIN | POLLOUT;
        ASSERT_EQ(Iouring::poll(fds, 1, 1000), 1);
        ASSERT_TRUE(fds[0].revents & POLLIN);
    });
}
