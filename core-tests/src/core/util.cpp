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

#include "swoole_util.h"

TEST(util, bitmap) {
    swoole::BitMap m(4096);

    m.set(199);
    m.set(1234);
    m.set(3048);

    ASSERT_EQ(m.get(199), true);
    ASSERT_EQ(m.get(1234), true);
    ASSERT_EQ(m.get(3048), true);

    ASSERT_EQ(m.get(2048), false);
    ASSERT_EQ(m.get(128), false);

    m.unset(1234);
    ASSERT_EQ(m.get(1234), false);

    m.clear();
}
