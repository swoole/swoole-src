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
#include "swoole_http.h"

#include <cstdlib>
#include <limits>

using swoole::http_server::url_decode;
using swoole::http_server::url_encode;

namespace {
size_t first_allocation_size;
void *first_allocation;
bool allocation_overrun;
size_t allocation_count;
size_t fail_allocation;
size_t live_allocations;

void *guarded_malloc(size_t size) {
    auto *buffer = static_cast<unsigned char *>(std::malloc(size + 16));
    if (buffer && !first_allocation) {
        first_allocation = buffer;
        first_allocation_size = size;
        memset(buffer + size, 0xa5, 16);
    }
    return buffer;
}

void guarded_free(void *buffer) {
    if (buffer == first_allocation) {
        auto *bytes = static_cast<unsigned char *>(buffer);
        for (size_t i = 0; i < 16; i++) {
            allocation_overrun |= bytes[first_allocation_size + i] != 0xa5;
        }
    }
    std::free(buffer);
}

void *failing_malloc(size_t size) {
    if (++allocation_count == fail_allocation) {
        errno = ENOMEM;
        return nullptr;
    }
    void *buffer = std::malloc(size);
    if (buffer) {
        live_allocations++;
    }
    return buffer;
}

void failing_free(void *buffer) {
    if (buffer) {
        live_allocations--;
    }
    std::free(buffer);
    errno = EINTR;
}
}  // namespace

TEST(http_url, terminator_stays_within_the_requested_allocation) {
    const std::vector<std::pair<std::string, size_t>> cases = {
        {"", 0},
        {" ", 3},
        {std::string(31, '\xff'), 93},
    };
    for (const auto &entry : cases) {
        SCOPED_TRACE(entry.first.size());
        EXPECT_EXIT(
            {
                first_allocation = nullptr;
                allocation_overrun = false;
                SwooleG.std_allocator.malloc = guarded_malloc;
                SwooleG.std_allocator.free = guarded_free;
                char *encoded = url_encode(entry.first.data(), entry.first.size());
                if (!encoded) {
                    _exit(2);
                }
                const bool length_valid = strlen(encoded) == entry.second;
                sw_free(encoded);
                _exit(length_valid && !allocation_overrun ? 0 : 1);
            },
            testing::ExitedWithCode(0),
            "");
    }
}

TEST(http_url, impossible_lengths_fail_before_reading_input) {
    const size_t maximum = std::numeric_limits<size_t>::max();
    for (const size_t length : {(maximum - 1) / 3 + 1, maximum}) {
        EXPECT_EXIT(
            {
                errno = 0;
                char *encoded = url_encode("x", length);
                _exit(encoded == nullptr && errno == EOVERFLOW ? 0 : 1);
            },
            testing::ExitedWithCode(0),
            "");
    }
}

TEST(http_url, allocation_failure_preserves_errno_and_releases_storage) {
    for (size_t fail_at : {1u, 2u}) {
        EXPECT_EXIT(
            {
                allocation_count = 0;
                live_allocations = 0;
                fail_allocation = fail_at;
                SwooleG.std_allocator.malloc = failing_malloc;
                SwooleG.std_allocator.free = failing_free;
                char *encoded = url_encode("a b", 3);
                const bool valid = encoded ? strcmp(encoded, "a%20b") == 0 : errno == ENOMEM;
                if (encoded) {
                    sw_free(encoded);
                }
                _exit(valid && live_allocations == 0 ? 0 : 1);
            },
            testing::ExitedWithCode(0),
            "");
    }
}

TEST(http_url, unreserved_bytes_and_explicit_length_keep_their_behavior) {
    const std::string literal = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    std::unique_ptr<char, decltype(&sw_free)> encoded(url_encode(literal.data(), literal.size()), sw_free);
    ASSERT_NE(encoded, nullptr);
    EXPECT_STREQ(encoded.get(), literal.c_str());
    encoded.reset(url_encode("a b?ignored", 3));
    ASSERT_NE(encoded, nullptr);
    EXPECT_STREQ(encoded.get(), "a%20b");
}

TEST(http_url, all_byte_values_keep_their_encoding_and_round_trip) {
    std::string input;
    for (unsigned int c = 0; c < 256; c++) {
        input.push_back(static_cast<char>(c));
    }
    std::unique_ptr<char, decltype(&sw_free)> encoded(url_encode(input.data(), input.size()), sw_free);
    ASSERT_NE(encoded, nullptr);
    EXPECT_EQ(strlen(encoded.get()), 636u);
    EXPECT_EQ(url_decode(encoded.get(), strlen(encoded.get())), input.size());
    EXPECT_EQ(memcmp(encoded.get(), input.data(), input.size()), 0);
}
