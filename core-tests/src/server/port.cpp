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

TEST(server_port, import) {
  ListenPort port(nullptr);
  ASSERT_FALSE(port.import(fileno(stdin)));
  ASSERT_ERREQ(ENOTSOCK);

  auto sock = swoole::make_socket(SW_SOCK_TCP, SW_FD_STREAM, 0);
  ASSERT_FALSE(port.import(sock->fd));
  ASSERT_ERREQ(EINVAL);
  sock->free();
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
  ASSERT_FALSE(port->ssl_context_create(port->ssl_context.get()));
  ASSERT_ERREQ(SW_ERROR_WRONG_OPERATION);
}

TEST(server_port, dgram) {
  Server server(Server::MODE_BASE);
  server.enable_reuse_port = true;
  auto port = server.add_port(SW_SOCK_UDP, TEST_HOST, 0);
  ASSERT_NE(nullptr, port);
  ASSERT_STREQ("dgram", port->get_protocols());
}