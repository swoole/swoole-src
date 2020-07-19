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

#include "test_core.h"

TEST(base, DataHead_dump) {
    swDataHead data = {};
    data.fd = 123;
    char buf[128];
    size_t n = data.dump(buf, sizeof(buf));

    ASSERT_GT(std::string(buf, n).find("int fd = 123;"), 1);
    ASSERT_EQ(sizeof(data), 16);
}

TEST(base, dec2hex) {
    auto result = swoole_dec2hex(2684326179, 16);
    ASSERT_STREQ(result, "9fff9123");
    sw_free(result);
}

TEST(base, swoole_hex2dec) {
    size_t n_parsed;
    ASSERT_EQ(swoole_hex2dec("9fff9123", &n_parsed), 2684326179);
    ASSERT_EQ(n_parsed, 8);
    ASSERT_EQ(swoole_hex2dec("0x9fff9123", &n_parsed), 2684326179);
    ASSERT_EQ(n_parsed, 10);
    ASSERT_EQ(swoole_hex2dec("f", &n_parsed), 15);
    ASSERT_EQ(n_parsed, 1);
}
