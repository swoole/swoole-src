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
#include "swoole_coroutine_socket.h"
#include "swoole_coroutine_system.h"

using namespace swoole::test;
using swoole::Coroutine;

TEST(coroutine_hook, accept) {
    coroutine::run([](void *arg) {
        // Create a TCP socket using coroutine API
        int server_sock = swoole_coroutine_socket(AF_INET, SOCK_STREAM, 0);
        ASSERT_GT(server_sock, 0);

        // Bind the socket to localhost with port 0 (auto-assign)
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        server_addr.sin_port = 0;

        int retval = ::bind(server_sock, (struct sockaddr *) &server_addr, sizeof(server_addr));
        ASSERT_EQ(retval, 0);

        // Listen on the socket
        retval = ::listen(server_sock, 128);
        ASSERT_EQ(retval, 0);

        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        // Test that swoole_coroutine_accept works correctly
        Coroutine::create([&](void *arg) {
            // Give the server time to start listening
            usleep(10000);

            // Connect to the server using coroutine API
            int client_sock = swoole_coroutine_socket(AF_INET, SOCK_STREAM, 0);
            ASSERT_GT(client_sock, 0);

            // Get the actual server port
            struct sockaddr_in actual_server_addr;
            socklen_t addr_len = sizeof(actual_server_addr);
            ASSERT_EQ(getsockname(server_sock, (struct sockaddr *) &actual_server_addr, &addr_len), 0);

            // Connect to the server
            retval = swoole_coroutine_connect(client_sock, (struct sockaddr *) &actual_server_addr, addr_len);
            ASSERT_EQ(retval, 0);

            // Send a test message
            const char *test_message = "test_data";
            ssize_t sent_bytes = swoole_coroutine_send(client_sock, test_message, strlen(test_message), 0);
            ASSERT_EQ(sent_bytes, (ssize_t) strlen(test_message));

            // Close the client socket
            swoole_coroutine_close(client_sock);
        });

        // Accept the connection using coroutine API
        int client_sock = swoole_coroutine_accept(server_sock, (struct sockaddr *) &client_addr, &client_addr_len);
        ASSERT_GT(client_sock, 0);

        // Receive data from client
        char buffer[256] = {};
        ssize_t received_bytes = swoole_coroutine_recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        ASSERT_GT(received_bytes, 0);
        ASSERT_STREQ(buffer, "test_data");

        // Close the client socket
        swoole_coroutine_close(client_sock);
        swoole_coroutine_close(server_sock);
    });
}

TEST(coroutine_hook, accept_optional_and_truncated_address) {
    coroutine::run([](void *arg) {
        int server_sock = swoole_coroutine_socket(AF_INET, SOCK_STREAM, 0);
        ASSERT_GT(server_sock, 0);

        struct sockaddr_in server_addr {};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        ASSERT_EQ(::bind(server_sock, (struct sockaddr *) &server_addr, sizeof(server_addr)), 0);
        ASSERT_EQ(::listen(server_sock, 128), 0);

        socklen_t server_len = sizeof(server_addr);
        ASSERT_EQ(getsockname(server_sock, (struct sockaddr *) &server_addr, &server_len), 0);

        Coroutine::create([&](void *arg) {
            for (int i = 0; i < 2; i++) {
                int fd = swoole_coroutine_socket(AF_INET, SOCK_STREAM, 0);
                ASSERT_EQ(swoole_coroutine_connect(fd, (struct sockaddr *) &server_addr, server_len), 0);
                swoole_coroutine_close(fd);
            }
        });

        // accept(2) allows a null address
        int fd = swoole_coroutine_accept(server_sock, nullptr, nullptr);
        ASSERT_GT(fd, 0);
        swoole_coroutine_close(fd);

        // The address is truncated to the caller's buffer while addrlen reports the full size
        struct {
            char buf[4];
            char guard[sizeof(sockaddr_in)];
        } peer;
        memset(&peer, 0x5a, sizeof(peer));
        socklen_t peer_len = sizeof(peer.buf);
        fd = swoole_coroutine_accept(server_sock, (struct sockaddr *) peer.buf, &peer_len);
        ASSERT_GT(fd, 0);
        ASSERT_EQ(peer_len, sizeof(sockaddr_in));
        for (char c : peer.guard) {
            ASSERT_EQ(c, 0x5a);
        }
        swoole_coroutine_close(fd);
        swoole_coroutine_close(server_sock);
    });
}
