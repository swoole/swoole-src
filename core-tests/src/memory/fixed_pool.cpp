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

#include <limits>

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

TEST(shared_memory, realloc_shrink_disallowed) {
    void *memory = sw_shm_malloc(128);
    ASSERT_NE(memory, nullptr);
    memset(memory, 0xAB, 128);

    void *new_memory = sw_shm_realloc(memory, 64);
    ASSERT_EQ(new_memory, nullptr);

    auto *buffer = static_cast<unsigned char *>(memory);
    ASSERT_EQ(buffer[0], 0xAB);
    ASSERT_EQ(buffer[127], 0xAB);
    sw_shm_free(memory);
}

TEST(shared_memory, calloc_overflow) {
    ASSERT_EQ(sw_shm_calloc(std::numeric_limits<size_t>::max(), 2), nullptr);
}

TEST(fixed_pool, constructor_overflow) {
    ASSERT_THROW(swoole::FixedPool(std::numeric_limits<uint32_t>::max(),
                                   std::numeric_limits<uint32_t>::max(),
                                   false),
                 swoole::Exception);
}

TEST(fixed_pool, exhaustion) {
    const uint32_t slice_num = 16;
    const uint32_t slice_size = 64;
    auto *pool = new swoole::FixedPool(slice_num, slice_size, false);

    ASSERT_EQ(pool->get_number_of_total_slice(), slice_num);
    ASSERT_EQ(pool->get_number_of_spare_slice(), slice_num);

    // allocate all slices
    std::vector<void *> ptrs;
    for (uint32_t i = 0; i < slice_num; i++) {
        void *ptr = pool->alloc(0);
        ASSERT_NE(ptr, nullptr);
        ptrs.push_back(ptr);
    }
    ASSERT_EQ(pool->get_number_of_spare_slice(), 0);

    // exhaustion: next alloc should return nullptr, not crash
    ASSERT_EQ(pool->alloc(0), nullptr);

    // free one slice and allocate again
    pool->free(ptrs.front());
    ASSERT_EQ(pool->get_number_of_spare_slice(), 1);
    void *ptr = pool->alloc(0);
    ASSERT_NE(ptr, nullptr);

    // write data to verify the slice is usable
    memset(ptr, 0xAB, slice_size);

    delete pool;
}

TEST(shared_memory, realloc_data) {
    const char *msg = "hello, swoole shared memory";
    size_t msg_len = strlen(msg) + 1;

    void *mem = sw_shm_malloc(msg_len);
    ASSERT_NE(mem, nullptr);
    memcpy(mem, msg, msg_len);

    void *new_mem = sw_shm_realloc(mem, msg_len * 2);
    ASSERT_NE(new_mem, nullptr);
    ON_SCOPE_EXIT {
        sw_shm_free(new_mem);
    };

    // verify data was correctly copied (regression test for buffer over-read fix)
    ASSERT_STREQ((char *) new_mem, msg);

    // write more data to the expanded region
    char *buf = (char *) new_mem;
    memset(buf + msg_len, 0xFF, msg_len);
    for (size_t i = 0; i < msg_len; i++) {
        ASSERT_EQ((unsigned char) buf[msg_len + i], 0xFF);
    }
}
