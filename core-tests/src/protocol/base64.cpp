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
#include "swoole_base64.h"

TEST(base64, encode) {
    char inbuf[1024];
    char outbuf[2048];

    auto n = swoole_random_bytes(inbuf, sizeof(inbuf) - 1);
    auto n2 = swoole::base64_encode((uchar *) inbuf, n, outbuf);
    ASSERT_GT(n2, n);
}

TEST(base64, decode) {
    const char *inbuf = "aGVsbG8gd29ybGQ=";
    char outbuf[2048];

    auto n2 = swoole::base64_decode(inbuf, strlen(inbuf), outbuf);
    ASSERT_EQ(std::string(outbuf, n2), "hello world");
}
