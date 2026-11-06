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

#include "swoole_server.h"
#include "test_server.h"

using swoole::ListenPort;
using swoole::Server;

TEST(server_port, ssl_wildcard_does_not_overlap_prefix_and_suffix) {
    EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("abc", "ab*bc"));
    EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("foo", "foo*foo"));
    EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("abc.example.com", "ab*bc.example.com"));
    EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("www.example.com", "*.example.com"));
    EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("foo.example.com", "foo*.example.com"));
    EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("foobar.example.com", "foo*bar.example.com"));
    EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("foo.bar.example.com", "foo*.example.com"));
}

TEST(server_port, import) {
    ListenPort port(nullptr);
    ASSERT_FALSE(port.import(fileno(stdin)));
    ASSERT_ERREQ(ENOTSOCK);

    auto sock = swoole::make_socket(SW_SOCK_TCP, SW_FD_STREAM, 0);
    ASSERT_FALSE(port.import(sock->fd));
    ASSERT_ERREQ(EINVAL);
    EXPECT_EQ(port.socket, nullptr);
    int socket_type;
    EXPECT_EQ(sock->get_option(SOL_SOCKET, SO_TYPE, &socket_type), SW_OK);
    EXPECT_EQ(socket_type, SOCK_STREAM);
    sock->free();
}

TEST(server_port, import_listening_socket) {
    ListenPort port(nullptr);
    auto *listener = swoole::make_server_socket(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_NE(listener, nullptr);
    const auto fd = listener->fd;
    const bool imported = port.import(fd);
    if (imported) {
        listener->move_fd();
    }
    listener->free();

    ASSERT_TRUE(imported);
    ASSERT_NE(port.socket, nullptr);
    EXPECT_EQ(port.socket->fd, fd);
    EXPECT_TRUE(port.listening);
    EXPECT_EQ(port.host, TEST_HOST);
    EXPECT_GT(port.port, 0);
}

TEST(server_port, create_socket_failure_can_retry) {
    Server server(Server::MODE_BASE);
    server.enable_reuse_port = false;
    ListenPort port(&server);
    port.type = SW_SOCK_TCP;
    port.host = TEST_HOST;
    port.port = -1;

    EXPECT_EQ(port.create_socket(), SW_ERR);
    EXPECT_EQ(port.socket, nullptr);
    port.port = 0;
    ASSERT_EQ(port.create_socket(), SW_OK);
    ASSERT_NE(port.socket, nullptr);
    EXPECT_GT(port.port, 0);
}

TEST(server_port, create) {
    Server server(Server::MODE_BASE);
    server.enable_reuse_port = true;
    auto port = server.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_NE(nullptr, port);
    ASSERT_EQ(SW_OK, port->create_socket());

    port->open_eof_check = true;
    port->protocol.package_eof_len = SW_DATA_EOF_MAXLEN + 10;
    port->init_protocol();
    ASSERT_STREQ("eof", port->get_protocols());
    ASSERT_EQ(port->protocol.package_eof_len, SW_DATA_EOF_MAXLEN);

    ASSERT_TRUE(port->ssl_context_init());
    ASSERT_FALSE(port->ssl_context_create(port->ssl_context.get(), false));
    ASSERT_ERREQ(SW_ERROR_WRONG_OPERATION);
    port->ssl_context->cert_file = "server.crt";
    ASSERT_FALSE(port->ssl_context_create(port->ssl_context.get(), true));
    port->ssl_context->cert_file.clear();
    ASSERT_TRUE(port->ssl_context_create(port->ssl_context.get(), true));
}

TEST(server_port, dgram) {
    Server server(Server::MODE_BASE);
    server.enable_reuse_port = true;
    auto port = server.add_port(SW_SOCK_UDP, TEST_HOST, 0);
    ASSERT_NE(nullptr, port);
    ASSERT_STREQ("dgram", port->get_protocols());
}
