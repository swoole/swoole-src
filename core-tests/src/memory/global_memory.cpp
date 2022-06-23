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
#include "swoole_memory.h"

TEST(global_memory, alloc) {
    auto pool = new swoole::GlobalMemory(2 * 1024 * 1024, false);

    char *ptr1 = (char *) pool->alloc(199);
    pool->free(ptr1);
    strcpy(ptr1, "hello, world, #1");

    char *ptr2 = (char *) pool->alloc(17);
    strcpy(ptr2, "hello, world, #2");
    pool->free(ptr2);

    char *ptr3 = (char *) pool->alloc(113);
    strcpy(ptr3, "hello, world, #3");

    ASSERT_TRUE(ptr1);
    ASSERT_TRUE(ptr2);
    ASSERT_TRUE(ptr3);

    ASSERT_GT(pool->capacity(), 2 * 1024 * 1024 - 512);
    ASSERT_GT(pool->get_memory_size(), 0);

    ASSERT_STREQ(ptr1, "hello, world, #1");
    ASSERT_STREQ(ptr2, "hello, world, #2");
    ASSERT_STREQ(ptr3, "hello, world, #3");

    pool->destroy();
    delete pool;
}
