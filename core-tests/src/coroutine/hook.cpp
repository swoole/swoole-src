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
#include "swoole_file.h"
#include "swoole_util.h"

using namespace swoole::test;

using swoole::Coroutine;
using swoole::String;
using swoole::coroutine::Socket;
using swoole::coroutine::System;
using swoole::test::coroutine;

const char *host_1 = "www.baidu.com";
const char *host_2 = "www.xxxxxxxxxxxxxxxxxxxxx00000xxxxxxxxx----not_found.com";
static const char *test_file = "/tmp/swoole-core-test";

TEST(coroutine_hook, file) {
    coroutine::run([](void *arg) {
        char buf[8192];
        size_t n_buf = sizeof(buf);
        ASSERT_EQ(swoole_random_bytes(buf, n_buf), n_buf);

        int fd = swoole_coroutine_open(test_file, O_WRONLY | O_TRUNC | O_CREAT, 0666);
        ASSERT_EQ(swoole_coroutine_write(fd, buf, n_buf), n_buf);
        swoole_coroutine_close(fd);

        fd = swoole_coroutine_open(test_file, O_RDONLY, 0);
        char data[8192];
        ASSERT_EQ(swoole_coroutine_read(fd, data, n_buf), n_buf);
        ASSERT_EQ(std::string(buf, n_buf), std::string(data, n_buf));
        swoole_coroutine_close(fd);

        ASSERT_EQ(swoole_coroutine_unlink(test_file), 0);
    });
}

TEST(coroutine_hook, gethostbyname) {
    coroutine::run([](void *arg) {
        auto result1 = swoole_coroutine_gethostbyname(host_1);
        ASSERT_NE(result1, nullptr);

        auto result2 = swoole_coroutine_gethostbyname(host_2);
        ASSERT_EQ(result2, nullptr);
        ASSERT_EQ(h_errno, HOST_NOT_FOUND);
    });
}

TEST(coroutine_hook, getaddrinfo) {
    coroutine::run([](void *arg) {
        struct addrinfo hints;
        sw_memset_zero(&hints, sizeof(struct addrinfo));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        struct addrinfo *result, *curr;
        int count;

        result = nullptr;
        auto result1 = swoole_coroutine_getaddrinfo(host_1, "http", &hints, &result);
        ASSERT_EQ(result1, 0);

        curr = result;
        count = 0;
        while (curr && curr->ai_addr) {
            curr = curr->ai_next;
            count++;
        }
        ASSERT_GE(count, 1);
        freeaddrinfo(result);

        result = nullptr;
        auto result2 = swoole_coroutine_getaddrinfo(host_2, nullptr, &hints, &result);
        ASSERT_EQ(result2, EAI_NONAME);
        ASSERT_EQ(result, nullptr);
        freeaddrinfo(result);
    });
}

TEST(coroutine_hook, fstat) {
    coroutine::run([](void *arg) {
        int fd = swoole_coroutine_open(TEST_TMP_FILE, O_RDONLY, 0);
        struct stat statbuf_1;
        swoole_coroutine_fstat(fd, &statbuf_1);

        struct stat statbuf_2;
        fstat(fd, &statbuf_2);

        ASSERT_EQ(memcmp(&statbuf_1, &statbuf_2, sizeof(statbuf_2)), 0);

        swoole_coroutine_close(fd);
    });
}

TEST(coroutine_hook, statvfs) {
    coroutine::run([](void *arg) {
        struct statvfs statbuf_1;
        swoole_coroutine_statvfs("/tmp", &statbuf_1);

        struct statvfs statbuf_2;
        statvfs("/tmp", &statbuf_2);

        ASSERT_EQ(memcmp(&statbuf_1, &statbuf_2, sizeof(statbuf_2)), 0);
    });
}

TEST(coroutine_hook, dir) {
    coroutine::run([](void *arg) {
        ASSERT_EQ(swoole_coroutine_mkdir(TEST_TMP_DIR, 0666), 0);
        ASSERT_EQ(swoole_coroutine_access(TEST_TMP_DIR, R_OK), 0);
        ASSERT_EQ(swoole_coroutine_rmdir(TEST_TMP_DIR), 0);
        ASSERT_EQ(access(TEST_TMP_DIR, R_OK), -1);
    });
}

TEST(coroutine_hook, socket) {
    coroutine::run([](void *arg) {
        int sock = swoole_coroutine_socket(AF_INET, SOCK_STREAM, 0);
        ASSERT_GT(sock, 0);
        swoole::network::Address sa;
        std::string ip = System::gethostbyname("www.baidu.com", AF_INET, 10);
        sa.assign(SW_SOCK_TCP, ip, 80);
        ASSERT_EQ(swoole_coroutine_connect(sock, &sa.addr.ss, sa.len), 0);
        ASSERT_EQ(swoole_coroutine_socket_wait_event(sock, SW_EVENT_WRITE, 5), SW_OK);

        const char req[] = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\nKeepAlive: off\r\n\r\n";
        ASSERT_EQ(swoole_coroutine_send(sock, req, strlen(req), 0), strlen(req));

        swoole::String resp(1024);

        while (1) {
            ssize_t n = swoole_coroutine_recv(sock, resp.value() + resp.length, resp.size - resp.length, 0);
            if (n <= 0) {
                break;
            }
            resp.length += n;
            if (resp.length == resp.size) {
                resp.reserve(resp.size * 2);
            }
        }

        ASSERT_GT(resp.length, 100);
        ASSERT_TRUE(resp.contains("baidu.com"));
        swoole_coroutine_close(sock);
    });
}

TEST(coroutine_hook, rename) {
    coroutine::run([](void *arg) {
        char buf[8192];
        size_t n_buf = sizeof(buf);
        ASSERT_EQ(swoole_random_bytes(buf, n_buf), n_buf);

        int fd = swoole_coroutine_open(test_file, O_WRONLY | O_TRUNC | O_CREAT, 0666);
        ASSERT_EQ(swoole_coroutine_write(fd, buf, n_buf), n_buf);
        swoole_coroutine_close(fd);

        std::string to_file_name = std::string(test_file, ".bak");
        ASSERT_EQ(swoole_coroutine_rename(test_file, to_file_name.c_str()), 0);
        ASSERT_EQ(access(TEST_TMP_DIR, F_OK), -1);
        ASSERT_EQ(access(to_file_name.c_str(), F_OK), 0);

        swoole_coroutine_unlink(to_file_name.c_str());
    });
}

TEST(coroutine_hook, flock) {
    long start_time = swoole::time<std::chrono::milliseconds>();
    coroutine::run([&](void *arg) {
        swoole::Coroutine::create([&](void *arg) {
            int fd = swoole_coroutine_open(TEST_TMP_FILE, O_WRONLY, 0);
            ASSERT_EQ(swoole_coroutine_flock(fd, LOCK_EX), 0);
            System::sleep(0.1);
            ASSERT_EQ(swoole_coroutine_flock(fd, LOCK_UN), 0);

            ASSERT_EQ(swoole_coroutine_flock(fd, LOCK_SH), 0);
            ASSERT_EQ(swoole_coroutine_flock(fd, LOCK_UN), 0);
            ASSERT_LE(swoole::time<std::chrono::milliseconds>() - start_time, 1000);
            swoole_coroutine_close(fd);
        });
        swoole::Coroutine::create([&](void *arg) {
            int fd = swoole_coroutine_open(TEST_TMP_FILE, O_WRONLY, 0);
            ASSERT_EQ(swoole_coroutine_flock(fd, LOCK_SH), 0);
            System::sleep(2);
            ASSERT_EQ(swoole_coroutine_flock(fd, LOCK_UN), 0);
            swoole_coroutine_close(fd);
        });
    });
    // LOCK_NB
    coroutine::run([](void *arg) {
        int fd1 = swoole_coroutine_open(TEST_TMP_FILE, O_WRONLY, 0);
        ASSERT_EQ(swoole_coroutine_flock(fd1, LOCK_EX), 0);
        int fd2 = swoole_coroutine_open(TEST_TMP_FILE, O_WRONLY, 0);
        ASSERT_EQ(swoole_coroutine_flock(fd2, LOCK_EX | LOCK_NB), -1);
        ASSERT_EQ(swoole_coroutine_flock(fd1, LOCK_UN), 0);
        swoole_coroutine_close(fd1);
        swoole_coroutine_close(fd2);
    });
}

TEST(coroutine_hook, read_dir) {
    auto fp = opendir("/tmp");
    std::string dir1(readdir(fp)->d_name);
    std::string dir2(readdir(fp)->d_name);
    closedir(fp);

    auto fn = [&]() {
        auto fp = swoole_coroutine_opendir("/tmp");
        ASSERT_NE(fp, nullptr);
        struct dirent *entry;

        entry = swoole_coroutine_readdir(fp);
        ASSERT_NE(entry, nullptr);
        ASSERT_STREQ(entry->d_name, dir1.c_str());

        entry = swoole_coroutine_readdir(fp);
        ASSERT_NE(entry, nullptr);
        ASSERT_STREQ(entry->d_name, dir2.c_str());

        swoole_coroutine_closedir(fp);
    };

    coroutine::run([&](void *arg) { fn(); });
    fn();
}

TEST(coroutine_hook, readlink) {
    auto fn = []() {
        char buf1[1024] = {};
        char buf2[1024] = {};

        auto retval = swoole_coroutine_readlink("/proc/self/cwd", buf1, sizeof(buf1));
        ASSERT_NE(retval, -1);

        getcwd(buf2, sizeof(buf2));
        ASSERT_STREQ(buf1, buf2);
    };

    coroutine::run([&](void *arg) { fn(); });
    fn();
}

TEST(coroutine_hook, stdio_1) {
    auto fn = []() {
        FILE *fp1 = swoole_coroutine_fopen(test_file, "w+");
        const char *str = "hello world";
        int n = swoole_coroutine_fputs(str, fp1);
        ASSERT_TRUE(n);
        swoole_coroutine_fclose(fp1);

        FILE *fp2 = swoole_coroutine_fopen(test_file, "r+");
        char buf[1024];
        char *str2 = swoole_coroutine_fgets(buf, sizeof(buf), fp2);

        ASSERT_STREQ(str2, str);
        swoole_coroutine_fclose(fp2);

        unlink(test_file);
    };

    coroutine::run([&](void *arg) { fn(); });
    fn();
}

TEST(coroutine_hook, stdio_2) {
    auto fn = []() {
        size_t size = 1024;

        FILE *fp1 = swoole_coroutine_fopen(test_file, "w+");
        String str(size);
        str.append_random_bytes(size);
        size_t n = swoole_coroutine_fwrite(str.str, 1, size, fp1);
        ASSERT_EQ(n, size);
        swoole_coroutine_fclose(fp1);

        FILE *fp2 = swoole_coroutine_fopen(test_file, "r+");
        char buf[size];
        size_t len = swoole_coroutine_fread(buf, 1, size, fp2);
        ASSERT_EQ(len, size);

        len = swoole_coroutine_fread(buf, 1, size, fp2);
        ASSERT_EQ(len, 0);

        ASSERT_TRUE(swoole_coroutine_feof(fp2));

        ASSERT_MEMEQ(buf, str.str, size);
        swoole_coroutine_fclose(fp2);

        unlink(test_file);
    };

    coroutine::run([&](void *arg) { fn(); });
    fn();
}

TEST(coroutine_hook, sleep) {
    coroutine::run([&](void *arg) {
        const int sec = 1;
        long sec_1 = swoole::time<std::chrono::seconds>();
        swoole_coroutine_sleep(sec);
        long sec_2 = swoole::time<std::chrono::seconds>();
        ASSERT_LE(sec_2 - sec_1, sec);

        const int us = 2000;
        long us_1 = swoole::time<std::chrono::milliseconds>();
        swoole_coroutine_usleep(us);
        long us_2 = swoole::time<std::chrono::milliseconds>();
        ASSERT_LE(us_2 - us_1, us / 1000);
    });
}

TEST(coroutine_hook, exists) {
    coroutine::run([&](void *arg) {
        const int fd = 100;  // fake fd
        ASSERT_EQ(swoole_coroutine_socket_create(fd), 0);
        ASSERT_TRUE(swoole_coroutine_socket_exists(fd));
        auto sock = swoole_coroutine_get_socket_object(fd);
        ASSERT_EQ(sock->get_fd(), fd);
        swoole_coroutine_close(fd);
    });
}

TEST(coroutine_hook, timeout) {
    coroutine::run([&](void *arg) {
        int pairs[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);
        std::string text = "Hello World";
        size_t length = text.length();

        // unregister fd
        ASSERT_EQ(swoole_coroutine_socket_set_timeout(pairs[0], SO_SNDTIMEO, 0.05), -1);

        swoole::Coroutine::create([&](void *) {
            ASSERT_EQ(swoole_coroutine_socket_create(pairs[0]), 0);

            // unknown which
            ASSERT_EQ(swoole_coroutine_socket_set_timeout(pairs[0], 100, 0.05), -1);

            swoole_coroutine_socket_set_timeout(pairs[0], SO_SNDTIMEO, 0.05);
            size_t result = swoole_coroutine_write(pairs[0], text.c_str(), length);
            ASSERT_EQ(swoole_coroutine_close(pairs[0]), 0);
            ASSERT_EQ(result, length);
        });

        char data[length + 1];
        ASSERT_EQ(swoole_coroutine_socket_create(pairs[1]), 0);
        swoole_coroutine_socket_set_timeout(pairs[1], SO_RCVTIMEO, 0.05);
        size_t result = swoole_coroutine_read(pairs[1], data, length);
        data[result] = '\0';
        ASSERT_EQ(swoole_coroutine_close(pairs[1]), 0);
        ASSERT_EQ(result, length);
        ASSERT_STREQ(data, text.c_str());
    });
}

TEST(coroutine_hook, sendmsg_and_recvmsg) {
    coroutine::run([&](void *arg) {
        int pairs[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);

        std::string text = "Hello World";
        size_t length = text.length();

        swoole::Coroutine::create([&](void *) {
            struct msghdr msg;
            struct iovec ivec;

            msg.msg_control = nullptr;
            msg.msg_controllen = 0;
            msg.msg_flags = 0;
            msg.msg_name = nullptr;
            msg.msg_namelen = 0;
            msg.msg_iov = &ivec;
            msg.msg_iovlen = 1;

            ivec.iov_base = (void *) text.c_str();
            ivec.iov_len = length;

            ssize_t ret = swoole_coroutine_sendmsg(pairs[0], &msg, 0);
            ASSERT_EQ(swoole_coroutine_close(pairs[0]), 0);
            ASSERT_EQ(ret, length);
        });

        struct msghdr msg;
        struct iovec ivec;
        char buf[length + 1];

        msg.msg_control = nullptr;
        msg.msg_controllen = 0;
        msg.msg_flags = 0;
        msg.msg_name = nullptr;
        msg.msg_namelen = 0;
        msg.msg_iov = &ivec;
        msg.msg_iovlen = 1;

        ivec.iov_base = buf;
        ivec.iov_len = length;

        ssize_t ret = swoole_coroutine_recvmsg(pairs[1], &msg, 0);
        buf[ret] = '\0';
        ASSERT_EQ(swoole_coroutine_close(pairs[1]), 0);
        ASSERT_STREQ(buf, text.c_str());
    });
}

TEST(coroutine_hook, lseek) {
    std::string file = get_jpg_file();
    int fd = swoole_coroutine_open(file.c_str(), O_RDONLY, 'r');
    off_t offset = swoole_coroutine_lseek(fd, 0, SEEK_SET);
    swoole_coroutine_close(fd);
    ASSERT_EQ(offset, 0);
}

extern std::pair<std::shared_ptr<Socket>, std::shared_ptr<Socket>> create_socket_pair();

TEST(coroutine_hook, socket_close) {
    coroutine::run([&](void *arg) {
        auto pair = create_socket_pair();

        auto buffer = sw_tg_buffer();
        buffer->clear();
        buffer->append_random_bytes(256 * 1024, false);

        std::map<std::string, bool> results;
        auto _sock = pair.first;
        auto _fd = _sock->move_fd();
        swoole_coroutine_socket_create(_fd);

        // write co
        Coroutine::create([&](void *) {
            SW_LOOP_N(32) {
                ssize_t result = swoole_coroutine_write(_fd, buffer->value(), buffer->get_length());
                if (result < 0 && errno == ECANCELED) {
                    ASSERT_EQ(swoole_coroutine_close(_fd), -1);
                    ASSERT_EQ(errno, SW_ERROR_CO_SOCKET_CLOSE_WAIT);
                    results["write"] = true;
                    break;
                }
            }
        });

        // read co
        Coroutine::create([&](void *) {
            SW_LOOP_N(32) {
                char buf[4096];
                ssize_t result = swoole_coroutine_read(_fd, buf, sizeof(buf));
                if (result < 0 && errno == ECANCELED) {
                    ASSERT_EQ(swoole_coroutine_close(_fd), 0);
                    results["read"] = true;
                    break;
                }
            }
        });

        System::sleep(0.1);
        ASSERT_EQ(swoole_coroutine_close(_fd), -1);
        ASSERT_EQ(errno, SW_ERROR_CO_SOCKET_CLOSE_WAIT);
        ASSERT_TRUE(results["write"]);
        ASSERT_TRUE(results["read"]);
    });
}

TEST(coroutine_hook, poll) {
    coroutine::run([&](void *arg) {
        auto pair = create_socket_pair();

        auto buffer = sw_tg_buffer();
        buffer->clear();
        buffer->append_random_bytes(256 * 1024, false);

        std::map<std::string, bool> results;
        auto _sock0 = pair.first;
        auto _fd0 = _sock0->move_fd();
        swoole_coroutine_socket_create(_fd0);

        auto _sock1 = pair.second;
        auto _fd1 = _sock1->move_fd();
        swoole_coroutine_socket_create(_fd1);

        Coroutine::create([&](void *) {
            ssize_t result;
            result = swoole_coroutine_write(_fd0, buffer->value(), buffer->get_length());
            ASSERT_GT(result, 0);            
            System::sleep(0.01);            
            result = swoole_coroutine_write(_fd1, buffer->value(), 16 * 1024);
            ASSERT_GT(result, 0);
        });

        struct pollfd fds[2];
        char buf[4096];

        bzero(fds, sizeof(pollfd));
        fds[0].fd = _fd0;
        fds[0].events = POLLIN;
        fds[1].fd = _fd1;
        fds[1].events = POLLIN;

        ASSERT_EQ(swoole_coroutine_poll(fds, 2, 1000), 1);
        ASSERT_TRUE(fds[1].revents & POLLIN);

        ssize_t result = swoole_coroutine_read(_fd1, buf, sizeof(buf));
        ASSERT_GT(result, 1024);

        System::sleep(0.02);  

        bzero(fds, sizeof(pollfd));
        fds[0].fd = _fd0;
        fds[0].events = POLLIN;
        fds[1].fd = _fd1;
        fds[1].events = POLLIN;

        ASSERT_EQ(swoole_coroutine_poll(fds, 2, 1000), 2);
        ASSERT_TRUE(fds[0].revents & POLLIN);
        ASSERT_TRUE(fds[1].revents & POLLIN);
        result = swoole_coroutine_read(_fd0, buf, sizeof(buf));
        ASSERT_GT(result, 1024);
        result = swoole_coroutine_read(_fd1, buf, sizeof(buf));
        ASSERT_GT(result, 1024);

        System::sleep(0.02);  

        bzero(fds, sizeof(pollfd));
        fds[0].fd = _fd0;
        fds[0].events = POLLIN | POLLOUT;
        fds[1].fd = _fd1;
        fds[1].events = POLLIN | POLLOUT;

        ASSERT_EQ(swoole_coroutine_poll(fds, 2, 1000), 2);
        ASSERT_TRUE(fds[0].revents & POLLIN);
        ASSERT_TRUE(fds[1].revents & POLLIN);
        ASSERT_FALSE(fds[0].revents & POLLOUT); // not writable
        ASSERT_TRUE(fds[1].revents & POLLOUT);
        result = swoole_coroutine_read(_fd0, buf, sizeof(buf));
        ASSERT_GT(result, 1024);
        result = swoole_coroutine_read(_fd1, buf, sizeof(buf));
        ASSERT_GT(result, 1024);
    });
}

TEST(coroutine_hook, poll_fake) {
    coroutine::run([&](void *arg) {
        auto pair = create_socket_pair();

        auto buffer = sw_tg_buffer();
        buffer->clear();
        buffer->append_random_bytes(256 * 1024, false);

        std::map<std::string, bool> results;
        auto _sock0 = pair.first;
        auto _fd0 = _sock0->move_fd();
        swoole_coroutine_socket_create(_fd0);

        auto _sock1 = pair.second;
        auto _fd1 = _sock1->move_fd();
        swoole_coroutine_socket_create(_fd1);

        Coroutine::create([&](void *) {
            ssize_t result;
            result = swoole_coroutine_write(_fd0, buffer->value(), buffer->get_length());
            ASSERT_GT(result, 0);
            System::sleep(0.01);
            result = swoole_coroutine_write(_fd1, buffer->value(), 16 * 1024);
            ASSERT_GT(result, 0);
        });

        struct pollfd fds[2];
        char buf[4096];

        bzero(fds, sizeof(pollfd));
        fds[0].fd = _fd1;
        fds[0].events = POLLIN;

        ASSERT_EQ(swoole_coroutine_poll_fake(fds, 1, 1000), 1);
        ASSERT_TRUE(fds[0].revents & POLLIN);

        ssize_t result = swoole_coroutine_read(_fd1, buf, sizeof(buf));
        ASSERT_GT(result, 1024);

        bzero(fds, sizeof(pollfd));
        ASSERT_EQ(swoole_coroutine_poll_fake(fds, 2, 1000), -1);
        ASSERT_EQ(swoole_get_last_error(), SW_ERROR_INVALID_PARAMS);

        System::sleep(0.02);

        bzero(fds, sizeof(pollfd));
        fds[0].fd = _fd0;
        fds[0].events = POLLIN | POLLOUT;
        ASSERT_EQ(swoole_coroutine_poll_fake(fds, 1, 1000), 1);
        ASSERT_TRUE(fds[0].revents & POLLIN);
        ASSERT_TRUE(fds[0].revents & POLLOUT);
    });
}