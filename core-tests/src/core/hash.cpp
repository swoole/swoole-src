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
#include "swoole_hash.h"

static const char *data = "hello world, PHP  the best.";

TEST(hash, crc32) {
    ASSERT_EQ(swoole_crc32(data, strlen(data)), 2962796788);
}

TEST(hash, php) {
    ASSERT_GT(swoole_hash_php(data, strlen(data)), 0);
}

TEST(hash, jenkins) {
    ASSERT_GT(swoole_hash_jenkins(data, strlen(data)), 0);
}

TEST(hash, austin) {
    ASSERT_GT(swoole_hash_austin(data, strlen(data)), 0);
}
