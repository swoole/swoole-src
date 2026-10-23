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
#include "swoole_buffer.h"

using namespace std;
using namespace swoole;

TEST(buffer, append_iov_boundaries_and_chunk_sizes) {
    const std::string segments[] = {"abc", std::string("d\0e", 3), "fghi"};
    iovec vectors[3];
    std::string combined;
    for (size_t i = 0; i < 3; i++) {
        vectors[i].iov_base = const_cast<char *>(segments[i].data());
        vectors[i].iov_len = segments[i].size();
        combined += segments[i];
    }
    for (uint32_t chunk_size : {0u, 1u, 4u, 64u}) {
        for (off_t offset : {-1, 0, 1, 3, 4, 6, 9, 10, 11}) {
            SCOPED_TRACE(chunk_size);
            SCOPED_TRACE(offset);
            Buffer buffer(chunk_size);
            buffer.append(vectors, 3, offset);
            const std::string expected =
                offset < 0 || static_cast<size_t>(offset) >= combined.size() ? "" : combined.substr(offset);
            EXPECT_EQ(buffer.length(), expected.size());
            const size_t capacity = chunk_size == 0 ? combined.size() : chunk_size;
            const size_t expected_chunks = (expected.size() + capacity - 1) / capacity;
            EXPECT_EQ(buffer.count(), expected_chunks);
            std::string actual;
            size_t remaining = expected.size();
            while (!buffer.empty()) {
                auto *chunk = buffer.front();
                ASSERT_EQ(chunk->type, BufferChunk::TYPE_DATA);
                ASSERT_GT(chunk->length, 0u);
                if (chunk_size != 0) {
                    EXPECT_LE(chunk->length, chunk_size);
                }
                actual.append(chunk->value.str, chunk->length);
                ASSERT_LE(chunk->length, remaining);
                remaining -= chunk->length;
                buffer.pop();
                EXPECT_EQ(buffer.length(), remaining);
            }
            EXPECT_EQ(actual, expected);
            EXPECT_EQ(remaining, 0u);
            EXPECT_EQ(buffer.count(), 0u);
            EXPECT_TRUE(Buffer::empty(&buffer));
        }
    }
}

TEST(buffer, empty_iov_append_preserves_existing_data) {
    Buffer buffer(4);
    buffer.append("keep", 4);
    buffer.append(nullptr, 0, 0);
    ASSERT_EQ(buffer.count(), 1u);
    EXPECT_EQ(buffer.length(), 4u);
    EXPECT_EQ(std::string(buffer.front()->value.str, buffer.front()->length), "keep");
    EXPECT_FALSE(Buffer::empty(&buffer));
    EXPECT_TRUE(Buffer::empty(nullptr));
}

TEST(buffer, append_binary_data_and_pop_tracks_remaining_length) {
    Buffer buffer(3);
    const std::string data("abc\0def", 7);
    buffer.append(data.data(), data.size());
    buffer.append("hi", 2);
    EXPECT_EQ(buffer.count(), 4u);
    std::string actual;
    size_t remaining = data.size() + 2;
    while (!buffer.empty()) {
        auto *chunk = buffer.front();
        actual.append(chunk->value.str, chunk->length);
        remaining -= chunk->length;
        buffer.pop();
        EXPECT_EQ(buffer.length(), remaining);
    }
    EXPECT_EQ(actual, data + "hi");
}

TEST(buffer, pop_and_destruction_release_control_chunks_once) {
    std::vector<BufferChunk::Type> destroyed;
    {
        Buffer buffer(4);
        for (const auto type : {BufferChunk::TYPE_SENDFILE, BufferChunk::TYPE_CLOSE}) {
            auto *chunk = buffer.alloc(type, 0);
            chunk->value.ptr = &destroyed;
            chunk->destroy = [](BufferChunk *chunk) {
                auto *destroyed = static_cast<std::vector<BufferChunk::Type> *>(chunk->value.ptr);
                destroyed->push_back(chunk->type);
            };
        }
        EXPECT_EQ(buffer.count(), 2u);
        EXPECT_EQ(buffer.length(), 0u);
        buffer.pop();
        EXPECT_EQ(destroyed, std::vector<BufferChunk::Type>{BufferChunk::TYPE_SENDFILE});
    }
    const std::vector<BufferChunk::Type> expected = {BufferChunk::TYPE_SENDFILE, BufferChunk::TYPE_CLOSE};
    EXPECT_EQ(destroyed, expected);
}
