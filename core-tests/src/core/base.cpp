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
#include "swoole_server.h"
#include "swoole_file.h"
#include "swoole_util.h"
#include "swoole.h"
#include "swoole_config.h"

using namespace swoole;
using namespace std;

static const string test_data("hello world\n");

TEST(base, datahead_dump) {
    swDataHead data = {};
    data.fd = 123;
    char buf[128];
    size_t n = data.dump(buf, sizeof(buf));
    data.print();

    ASSERT_GT(std::string(buf, n).find("int fd = 123;"), 1);
}

TEST(base, dec2hex) {
    auto result = swoole_dec2hex(2684326179, 16);
    ASSERT_STREQ(result, "9fff9123");
    sw_free(result);
}

TEST(base, hex2dec) {
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
    ASSERT_TRUE(file_put_contents(TEST_TMP_FILE, buf, sizeof(buf)));
    auto result = file_get_contents(TEST_TMP_FILE);
    ASSERT_STREQ(buf, result->value());
}

TEST(base, file_get_size) {
    File f(TEST_TMP_FILE, File::WRITE | File::CREATE);
    char buf[65536];
    swoole_random_string(buf, sizeof(buf) - 1);

    ASSERT_TRUE(f.ready());
    f.truncate(0);
    f.set_offest(0);
    f.write(buf, sizeof(buf) - 1);
    f.close();

    ASSERT_EQ(file_get_size(TEST_TMP_FILE), sizeof(buf) - 1);
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

    str = "md5sum test.abcdef";
    _pipe = swoole_shell_exec(str.c_str(), &pid, 1);
    memset(buf, 0, sizeof(buf));
    ssize_t length = 0;
    while (1) {
        n = read(_pipe, buf + length, sizeof(buf) - 1 - length);
        length += n;
        if (n > 0) {
            continue;
        }
        break;
    }
    ASSERT_GT(length, 0);

    ASSERT_STREQ(buf, string("md5sum: test.abcdef: No such file or directory\n").c_str());
    close(_pipe);
}

TEST(base, file_size) {
    auto file = test::get_jpg_file();
    ssize_t file_size = file_get_size(file);
    ASSERT_GT(file_size, 0);
    auto fp = fopen(file.c_str(), "r+");
    ASSERT_TRUE(fp);
    ASSERT_EQ(file_get_size(fp), file_size);
    fclose(fp);
}

TEST(base, eventdata_pack) {
    EventData ed1{};

    ASSERT_TRUE(Server::task_pack(&ed1, test_data.c_str(), test_data.length()));
    ASSERT_EQ(string(ed1.data, ed1.info.len), test_data);

    EventData ed2{};
    ASSERT_EQ(swoole_random_bytes(sw_tg_buffer()->str, SW_BUFFER_SIZE_BIG), SW_BUFFER_SIZE_BIG);
    ASSERT_TRUE(Server::task_pack(&ed2, sw_tg_buffer()->str, SW_BUFFER_SIZE_BIG));

    String _buffer(SW_BUFFER_SIZE_BIG);
    PacketPtr packet;
    ASSERT_TRUE(Server::task_unpack(&ed2, &_buffer, &packet));
    ASSERT_EQ(memcmp(sw_tg_buffer()->str, _buffer.str, SW_BUFFER_SIZE_BIG), 0);
}

TEST(base, stack_defer_fn) {
    int count = 0;

    ON_SCOPE_EXIT {
        count++;
        ASSERT_EQ(count, 2);
    };

    ON_SCOPE_EXIT {
        count++;
        ASSERT_EQ(count, 1);
    };
}

TEST(base, string_format) {
    char *data = swoole_string_format(128, "hello %d world, %s is best.", 2020, "swoole");
    ASSERT_STREQ(data, "hello 2020 world, swoole is best.");
    sw_free(data);
}

TEST(base, dirname) {
    ASSERT_EQ(dirname("/hello/world/index.html.abc"), "/hello/world");
    ASSERT_EQ(dirname("/hello/world"), "/hello");
    ASSERT_EQ(dirname("/root"), "/");
    ASSERT_EQ(dirname("/"), "/");
}

TEST(base, set_task_tmpdir) {
    ASSERT_FALSE(swoole_set_task_tmpdir("aaa"));

    size_t length = SW_TASK_TMP_PATH_SIZE + 1;
    char too_long_dir[length] = {};
    swoole_random_string(too_long_dir + 1, length - 1);
    too_long_dir[0] = '/';
    ASSERT_FALSE(swoole_set_task_tmpdir(too_long_dir));

    const char *tmpdir = "/tmp/swoole/core_tests/base";
    ASSERT_TRUE(swoole_set_task_tmpdir(tmpdir));
    File fp = swoole::make_tmpfile();
    ASSERT_TRUE(fp.ready());

    char buf[128];
    swoole_random_string(buf, sizeof(buf) - 2);
    buf[sizeof(buf) - 2] = '\n';

    fp.write(buf, sizeof(buf) - 1);
    fp.close();

    ASSERT_EQ(swoole::dirname(fp.get_path()), tmpdir);
    ASSERT_STREQ(swoole::file_get_contents(fp.get_path())->str, buf);

    unlink(fp.get_path().c_str());
    rmdir(tmpdir);
}

TEST(base, version) {
    ASSERT_STREQ(swoole_version(), SWOOLE_VERSION);
    ASSERT_EQ(swoole_version_id(), SWOOLE_VERSION_ID);
    ASSERT_EQ(swoole_api_version_id(), SWOOLE_API_VERSION_ID);
}

static std::string test_func(std::string test_data_2) {
    return test_data + test_data_2;
}

TEST(base, add_function) {
    typedef std::string (*_func_t)(std::string);
    swoole_add_function("test_func", (void *) test_func);
    ASSERT_EQ(swoole_add_function("test_func", (void *) test_func), SW_ERR);
    _func_t _func = (_func_t) swoole_get_function(SW_STRL("test_func"));
    std::string b = ", swoole is best";
    auto rs = _func(", swoole is best");
    ASSERT_EQ(rs, test_data + b);
    ASSERT_EQ(swoole_get_function(SW_STRL("test_func31")), nullptr);
}

TEST(base, hook) {
    int count = 0;
    swoole_add_hook(
        SW_GLOBAL_HOOK_END,
        [](void *data) -> void {
            int *_count = (int *) data;
            *_count = 9999;
        },
        1);
    ASSERT_TRUE(swoole_isset_hook(SW_GLOBAL_HOOK_END));
    swoole_call_hook(SW_GLOBAL_HOOK_END, &count);
    ASSERT_EQ(count, 9999);
}

TEST(base, intersection) {
    std::vector<std::string> vec1{"index.php", "index.html", "default.html"};

    std::set<std::string> vec2{".", "..", "default.html", "index.php", "test.html", "a.json", "index.php"};
    ASSERT_EQ("index.php", swoole::intersection(vec1, vec2));

    std::set<std::string> vec3{"a", "zh中", "、r\n"};
    ASSERT_EQ("", swoole::intersection(vec1, vec3));
}

TEST(base, itoa) {
    char buf[128];
    long value = 123456987;
    int n = swoole_itoa(buf, value);

    ASSERT_EQ(n, 9);
    ASSERT_STREQ(buf, "123456987");
}

TEST(base, get_systemd_listen_fds) {
    ASSERT_EQ(swoole_get_systemd_listen_fds(), -1);
    setenv("LISTEN_FDS", to_string(SW_MAX_LISTEN_PORT + 1).c_str(), 1);
    ASSERT_EQ(swoole_get_systemd_listen_fds(), -1);
    setenv("LISTEN_FDS", to_string(SW_MAX_LISTEN_PORT - 1).c_str(), 1);
    ASSERT_EQ(swoole_get_systemd_listen_fds(), SW_MAX_LISTEN_PORT - 1);
}

TEST(base, type_size) {
    ASSERT_EQ(swoole_type_size('c'), 1);
    ASSERT_EQ(swoole_type_size('s'), 2);
    ASSERT_EQ(swoole_type_size('l'), 4);
    ASSERT_EQ(swoole_type_size('b'), 0);  // default value
}

size_t swoole_fatal_error_impl(const char *format, ...) {
    size_t retval = 0;
    va_list args;
    va_start(args, format);

    char buf[128];
    retval += sw_vsnprintf(buf, 128, format, args);
    va_end(args);
    return retval;
}

TEST(base, vsnprintf) {
    ASSERT_GT(swoole_fatal_error_impl("Hello %s", "World!!!"), 0);
}

TEST(base, log_level) {
    int level = sw_logger()->get_level();
    swoole_set_log_level(SW_LOG_TRACE);
    swoole_print_backtrace();
    EXPECT_EQ(SW_LOG_TRACE, sw_logger()->get_level());
    swoole_set_log_level(level);
}

TEST(base, trace_flag) {
    int flags = SwooleG.trace_flags;
    swoole_set_trace_flags(SW_TRACE_CARES);
    EXPECT_EQ(SW_TRACE_CARES, SwooleG.trace_flags);
    swoole_set_trace_flags(flags);
}

TEST(base, only_dump) {
    // just dump something
    std::string data = "hello world";
    swoole_dump_ascii(data.c_str(), data.length());
    swoole_dump_bin(data.c_str(), 'C', data.length());
    swoole_dump_hex(data.c_str(), data.length());
    ASSERT_TRUE(true);
}
