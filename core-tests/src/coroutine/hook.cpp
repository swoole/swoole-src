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

#include "test_coroutine.h"

using swoole::Coroutine;
using swoole::coroutine::System;
using swoole::test::coroutine;

const char *host_1 = "www.baidu.com";
const char *host_2 = "www.xxxxxxxxxxxxxxxxxxxxx00000xxxxxxxxx----not_found.com";

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
        std::string ip = System::gethostbyname( "www.baidu.com", AF_INET, 10);
        sa.assign(SW_SOCK_TCP, ip.c_str(), 80);
        ASSERT_EQ(swoole_coroutine_connect(sock, &sa.addr.ss, sa.len), 0);
        ASSERT_EQ(swoole_coroutine_socket_wait_event(sock, SW_EVENT_WRITE, 5), SW_OK);

        const char req[] = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\nKeepAlive: off\r\n\r\n";
        ASSERT_EQ(swoole_coroutine_send(sock, req, strlen(req), 0), strlen(req));

        swoole::String resp(1024);

        while(1) {
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
