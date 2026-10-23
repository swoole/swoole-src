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

#include <stdexcept>
#include <vector>

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

    delete pool;
}

namespace {
class GlobalMemoryTest : public testing::TestWithParam<bool> {
  protected:
    const uint32_t page_size = static_cast<uint32_t>(swoole_pagesize());
};
}  // namespace

TEST_P(GlobalMemoryTest, allocations_are_zeroed_aligned_and_independent) {
    swoole::GlobalMemory pool(page_size, GetParam());
    std::vector<std::pair<char *, size_t>> allocations;
    for (const uint32_t size : {1u, 7u, 8u, 9u, 31u, 63u}) {
        auto *memory = static_cast<char *>(pool.alloc(size));
        ASSERT_NE(memory, nullptr);
        EXPECT_EQ(reinterpret_cast<uintptr_t>(memory) % SW_DEFAULT_ALIGNMENT, 0u);
        EXPECT_EQ(std::string(memory, size), std::string(size, '\0'));
        memset(memory, static_cast<int>(size), size);
        allocations.emplace_back(memory, size);
    }
    for (const auto &allocation : allocations) {
        EXPECT_EQ(std::string(allocation.first, allocation.second),
                  std::string(allocation.second, static_cast<char>(allocation.second)));
    }
    EXPECT_EQ(pool.get_memory_size(), page_size);
}

TEST_P(GlobalMemoryTest, exact_page_fill_rolls_over_without_invalidating_old_allocations) {
    swoole::GlobalMemory pool(page_size, GetParam());
    const auto initial_capacity = pool.capacity();
    auto *first = static_cast<char *>(pool.alloc(1));
    ASSERT_NE(first, nullptr);
    *first = 'x';
    const auto block_overhead = initial_capacity - pool.capacity() - SW_MEM_ALIGNED_SIZE(1);
    // Fill one chunk using several small allocations, each within its half-chunk limit.
    auto *middle = static_cast<char *>(pool.alloc(page_size / 2));
    ASSERT_NE(middle, nullptr);
    memset(middle, 'm', page_size / 2);
    const auto remaining_payload = pool.capacity() - block_overhead;
    auto *tail = static_cast<char *>(pool.alloc(remaining_payload));
    ASSERT_NE(tail, nullptr);
    EXPECT_EQ(std::string(tail, remaining_payload), std::string(remaining_payload, '\0'));
    memset(tail, 't', remaining_payload);
    EXPECT_EQ(pool.capacity(), 0u);
    EXPECT_EQ(pool.get_memory_size(), page_size);
    auto *next = static_cast<char *>(pool.alloc(1));
    ASSERT_NE(next, nullptr);
    EXPECT_EQ(*next, '\0');
    EXPECT_EQ(pool.get_memory_size(), page_size * 2);
    EXPECT_EQ(*first, 'x');
    EXPECT_EQ(std::string(middle, page_size / 2), std::string(page_size / 2, 'm'));
    EXPECT_EQ(std::string(tail, remaining_payload), std::string(remaining_payload, 't'));
}

TEST_P(GlobalMemoryTest, oversized_requests_throw_without_changing_pool_state) {
    swoole::GlobalMemory pool(page_size, GetParam());
    auto *memory = static_cast<char *>(pool.alloc(4));
    ASSERT_NE(memory, nullptr);
    memcpy(memory, "kept", 4);
    const auto capacity = pool.capacity();
    EXPECT_THROW(pool.alloc(page_size / 2 + 1), std::invalid_argument);
    EXPECT_THROW(pool.alloc(page_size), std::invalid_argument);
    EXPECT_THROW(pool.alloc(page_size + 1), std::invalid_argument);
    // These requests wrapped to zero before the size was validated.
    EXPECT_THROW(pool.alloc(UINT32_MAX), std::invalid_argument);
    EXPECT_THROW(pool.alloc(UINT32_MAX - 1), std::invalid_argument);
    EXPECT_EQ(pool.capacity(), capacity);
    EXPECT_EQ(pool.get_memory_size(), page_size);
    EXPECT_EQ(std::string(memory, 4), "kept");
    auto *next = static_cast<char *>(pool.alloc(4));
    ASSERT_NE(next, nullptr);
    EXPECT_EQ(std::string(next, 4), std::string(4, '\0'));
}

TEST_P(GlobalMemoryTest, half_chunk_limit_is_inclusive) {
    swoole::GlobalMemory pool(page_size, GetParam());
    const auto limit = page_size / 2;
    auto *first = static_cast<char *>(pool.alloc(limit - 1));
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(std::string(first, limit - 1), std::string(limit - 1, '\0'));
    memset(first, 'a', limit - 1);
    auto *second = static_cast<char *>(pool.alloc(limit));
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(std::string(second, limit), std::string(limit, '\0'));
    EXPECT_EQ(pool.get_memory_size(), page_size * 2);
    EXPECT_EQ(std::string(first, limit - 1), std::string(limit - 1, 'a'));
}

TEST_P(GlobalMemoryTest, free_does_not_reclaim_or_overwrite_global_allocations) {
    swoole::GlobalMemory pool(page_size, GetParam());
    auto *first = static_cast<char *>(pool.alloc(16));
    ASSERT_NE(first, nullptr);
    memset(first, 'a', 16);
    const auto capacity = pool.capacity();
    pool.free(first);
    EXPECT_EQ(pool.capacity(), capacity);
    auto *second = static_cast<char *>(pool.alloc(16));
    ASSERT_NE(second, nullptr);
    EXPECT_NE(first, second);
    EXPECT_EQ(std::string(second, 16), std::string(16, '\0'));
    EXPECT_EQ(std::string(first, 16), std::string(16, 'a'));
}

INSTANTIATE_TEST_SUITE_P(MemoryTypes, GlobalMemoryTest, testing::Bool(), [](const testing::TestParamInfo<bool> &info) {
    return info.param ? "Shared" : "Private";
});
