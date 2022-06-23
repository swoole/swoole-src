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
#include "swoole_util.h"

using namespace std;

TEST(fixed_pool, alloc) {
    auto *pool = new swoole::FixedPool(1024, 256, false);

    list<void *> alloc_list;
    ASSERT_EQ(pool->get_slice_size(), 256);

    for (int i = 0; i < 1200; i++) {
        int j = rand();
        void *mem;

        if (j % 4 < 3) {
            mem = pool->alloc(0);
            ASSERT_TRUE(mem);
            alloc_list.push_back(mem);
        } else if (!alloc_list.empty()) {
            if (j % 2 == 1) {
                mem = alloc_list.front();
                alloc_list.pop_front();
            } else {
                mem = alloc_list.back();
                alloc_list.pop_back();
            }
            pool->free(mem);
        }
    }
    pool->debug(1);
    delete pool;
}

TEST(fixed_pool, realloc) {
    void *memory = sw_shm_malloc(1024);
    void *new_memory = sw_shm_realloc(memory, 2048);
    ON_SCOPE_EXIT {
        sw_shm_free(new_memory);
    };
    ASSERT_NE(new_memory, nullptr);

}
