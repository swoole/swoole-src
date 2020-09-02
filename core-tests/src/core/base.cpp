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

#include "test_core.h"

using namespace swoole;
using namespace std;

static const string test_data("hello world\n");

TEST(base, DataHead_dump) {
    swDataHead data = {};
    data.fd = 123;
    char buf[128];
    size_t n = data.dump(buf, sizeof(buf));

    ASSERT_GT(std::string(buf, n).find("int fd = 123;"), 1);
    ASSERT_EQ(sizeof(data), 16);
}

TEST(base, dec2hex) {
    auto result = swoole_dec2hex(2684326179, 16);
    ASSERT_STREQ(result, "9fff9123");
    sw_free(result);
}

TEST(base, swoole_hex2dec) {
    size_t n_parsed;
    ASSERT_EQ(swoole_hex2dec("9fff9123", &n_parsed), 2684326179);
    ASSERT_EQ(n_parsed, 8);
    ASSERT_EQ(swoole_hex2dec("0x9fff9123", &n_parsed), 2684326179);
    ASSERT_EQ(n_parsed, 10);
    ASSERT_EQ(swoole_hex2dec("f", &n_parsed), 15);
    ASSERT_EQ(n_parsed, 1);
}

TEST(base, random_string) {
    char buf[1024] = {};
    swoole_random_string(buf, sizeof(buf) - 1);
    ASSERT_EQ(strlen(buf), sizeof(buf) - 1);
}

TEST(base, file_put_contents) {
    char buf[65536];
    swoole_random_string(buf, sizeof(buf) - 1);
    ASSERT_TRUE(swoole_file_put_contents(TEST_TMP_FILE, buf, sizeof(buf)));
    auto result = swoole_file_get_contents(TEST_TMP_FILE);
    ASSERT_STREQ(buf, result->value());
}

TEST(base, version_compare) {
    ASSERT_EQ(swoole_version_compare("1.2.1", "1.2.0"), 1);
    ASSERT_EQ(swoole_version_compare("1.2.3", "1.3.0"), -1);
    ASSERT_EQ(swoole_version_compare("1.2.3", "1.2.9"), -1);
    ASSERT_EQ(swoole_version_compare("1.2.0", "1.2.0"), 0);
}

TEST(base, common_divisor) {
    ASSERT_EQ(swoole_common_divisor(16, 12), 4);
    ASSERT_EQ(swoole_common_divisor(6, 15), 3);
    ASSERT_EQ(swoole_common_divisor(32, 16), 16);
}

TEST(base, common_multiple) {
    ASSERT_EQ(swoole_common_multiple(16, 12), 48);
    ASSERT_EQ(swoole_common_multiple(6, 15), 30);
    ASSERT_EQ(swoole_common_multiple(32, 16), 32);
}

TEST(base, shell_exec) {
    pid_t pid;
    string str = "md5sum " + test::get_jpg_file();
    int _pipe = swoole_shell_exec(str.c_str(), &pid, 0);
    ASSERT_GT(_pipe, 0);
    ASSERT_GT(pid, 0);
    char buf[1024] = {};
    ssize_t n = read(_pipe, buf, sizeof(buf) - 1);
    ASSERT_GT(n, 0);
    ASSERT_STREQ(string(buf).substr(0, sizeof(TEST_JPG_MD5SUM) - 1).c_str(), TEST_JPG_MD5SUM);
    close(_pipe);
}

TEST(base, file_size) {
    auto file = test::get_jpg_file();
    ssize_t file_size = swoole_file_size(file.c_str());
    ASSERT_GT(file_size, 0);
    auto fp = fopen(file.c_str(), "r+");
    ASSERT_TRUE(fp);
    ASSERT_EQ(swoole_file_get_size(fp), file_size);
    fclose(fp);
}

TEST(base, eventdata_pack) {
    swEventData ed1 { };

    ASSERT_TRUE(ed1.pack(test_data.c_str(), test_data.length()));
    ASSERT_EQ(string(ed1.data, ed1.info.len), test_data);

    swEventData ed2 { };
    ASSERT_EQ(swoole_random_bytes(SwooleTG.buffer_stack->str, SW_BUFFER_SIZE_BIG), SW_BUFFER_SIZE_BIG);
    ASSERT_TRUE(ed2.pack(SwooleTG.buffer_stack->str, SW_BUFFER_SIZE_BIG));

    String _buffer(SW_BUFFER_SIZE_BIG);
    ASSERT_TRUE(ed2.unpack(&_buffer));
    ASSERT_EQ(memcmp(SwooleTG.buffer_stack->str, _buffer.str, SW_BUFFER_SIZE_BIG), 0);
}
