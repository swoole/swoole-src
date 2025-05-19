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

static const int hash_count = 8192;
static const int str_max_len = 1024;
static const char *data = "hello world, PHP  the best.";

TEST(hash, crc32) {
    ASSERT_EQ(swoole_crc32(data, strlen(data)), 2962796788);
}

static void test_hash_func(uint64_t (*hash_fn)(const char *key, size_t len), int n) {
    std::vector<uint64_t> hashes;
    std::vector<std::string> data;
    hashes.resize(n);
    data.resize(n);

    SW_LOOP_N(n) {
        size_t len = 1 + swoole_random_int() % str_max_len;
        char buf[str_max_len];
        ASSERT_EQ(swoole_random_bytes(buf, len), len);
        hashes[i] = hash_fn(buf, len);
        data[i] = std::string(buf, len);
    }

    usleep(100);

    SW_LOOP_N(n) {
        auto &s = data.at(i);
        ASSERT_EQ(hashes[i], hash_fn(s.c_str(), s.length()));
    }
}

TEST(hash, php) {
    test_hash_func(swoole_hash_jenkins, hash_count);
}

TEST(hash, jenkins) {
    test_hash_func(swoole_hash_jenkins, hash_count);
}

TEST(hash, austin) {
    test_hash_func(swoole_hash_austin, hash_count);
}
