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

#include "tests.h"
#include "swoole_memory.h"

TEST(global_memory, alloc)
{
    auto m = swMemoryGlobal_new(2 * 1024 * 1024, false);

    void *ptr1 = m->alloc(m, 199);
    m->free(m, ptr1);

    void *ptr2 = m->alloc(m, 12);
    void *ptr3 = m->alloc(m, 198);

    ASSERT_EQ(ptr1, ptr3);
    ASSERT_NE(ptr1, ptr2);
}
