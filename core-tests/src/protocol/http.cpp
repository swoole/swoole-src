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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "test_core.h"
#include "swoole_proxy.h"

using swoole::HttpProxy;

TEST(http_proxy, parse_response) {
    size_t response_length = 0;

    ASSERT_EQ(HttpProxy::parse_response(SW_STRL("HTTP/1."), &response_length), SW_HTTP_PROXY_RESPONSE_WAIT);
    ASSERT_EQ(HttpProxy::parse_response(SW_STRL("not-http"), &response_length), SW_HTTP_PROXY_RESPONSE_ERROR);
    ASSERT_EQ(HttpProxy::parse_response(SW_STRL("HTTP/1.1 200 Connection established\r\n"), &response_length),
              SW_HTTP_PROXY_RESPONSE_WAIT);
    ASSERT_EQ(HttpProxy::parse_response(SW_STRL("HTTP/1.1 407 Proxy Authentication Required\r\n"), &response_length),
              SW_HTTP_PROXY_RESPONSE_ERROR);
    ASSERT_EQ(HttpProxy::parse_response(SW_STRL("HTTP/1.1 2000 OK\r\n\r\n"), &response_length),
              SW_HTTP_PROXY_RESPONSE_ERROR);
    ASSERT_EQ(HttpProxy::parse_response(SW_STRL("HTTP/2 200 OK\r\n\r\n"), &response_length),
              SW_HTTP_PROXY_RESPONSE_ERROR);

    const char response_1_0[] = "HTTP/1.0 200\r\n\r\n";
    ASSERT_EQ(HttpProxy::parse_response(SW_STRL(response_1_0), &response_length), SW_HTTP_PROXY_RESPONSE_READY);
    ASSERT_EQ(response_length, sizeof(response_1_0) - 1);

    const char response[] = "HTTP/1.1 200 OK\r\nProxy-Agent: test\r\n\r\nTUNNEL DATA";
    ASSERT_EQ(HttpProxy::parse_response(SW_STRL(response), &response_length), SW_HTTP_PROXY_RESPONSE_READY);
    ASSERT_EQ(response_length, sizeof("HTTP/1.1 200 OK\r\nProxy-Agent: test\r\n\r\n") - 1);

    const char response_without_reason[] = "HTTP/1.1 200\r\n\r\n";
    ASSERT_EQ(HttpProxy::parse_response(SW_STRL(response_without_reason), &response_length),
              SW_HTTP_PROXY_RESPONSE_READY);
    ASSERT_EQ(response_length, sizeof(response_without_reason) - 1);
}
