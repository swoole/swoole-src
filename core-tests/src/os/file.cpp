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

#include "swoole_file.h"
#include "swoole_pipe.h"

using namespace swoole;

TEST(file, read_line) {
    std::string filename = test::get_root_path() + "/tests/include/bootstrap.php";
    File file(filename, File::READ);
    FILE *stdc_file = fopen(filename.c_str(), "r");
    ASSERT_NE(stdc_file, nullptr);
    char buf1[1024];
    char buf2[1024];

    size_t size = file.get_size();
    size_t total = 0;

    while (true) {
        auto retval = file.read_line(buf1, sizeof(buf1));
        if (retval == 0) {
            break;
        }
        total += retval;
        ASSERT_NE(fgets(buf2, sizeof(buf2), stdc_file), nullptr);
        ASSERT_STREQ(buf1, buf2);
    }
    ASSERT_EQ(total, size);
}

TEST(file, read_line_no_crlf) {
    String buf(1024);
    swoole_random_string(buf.str, buf.size - 1);
    buf.str[buf.size - 1] = '\0';

    std::string filename = "/tmp/swoole_file_read_line_no_crlf.txt";
    ASSERT_TRUE(file_put_contents(filename, buf.str, buf.size - 1));

    File file(filename, File::READ);
    char rbuf[1024];
    ASSERT_EQ(file.read_line(rbuf, sizeof(rbuf)), sizeof(rbuf) - 1);
    ASSERT_EQ(rbuf[sizeof(rbuf) - 1], '\0');

    remove(filename.c_str());
}

TEST(file, file_put_contents) {
    std::string filename = "/tmp/not-exists-dir/test.txt";

    ASSERT_FALSE(file_put_contents(filename, TEST_STR, 0));
    ASSERT_ERREQ(SW_ERROR_FILE_EMPTY);

    ASSERT_FALSE(file_put_contents(filename, TEST_STR, SwooleG.max_file_content + 1));
    ASSERT_ERREQ(SW_ERROR_FILE_TOO_LARGE);

    ASSERT_FALSE(file_put_contents(filename, SW_STRL(TEST_STR)));
    ASSERT_ERREQ(ENOENT);
}

TEST(file, file_get_contents) {
    std::string filename = "/tmp/not-exists-dir/test.txt";

    ASSERT_EQ(file_get_contents(filename), nullptr);
    ASSERT_ERREQ(ENOENT);

    ASSERT_EQ(file_get_contents("/tmp"), nullptr);
    ASSERT_ERREQ(EISDIR);

    auto empty_file = "/tmp/empty-file.txt";
    int fd = open(empty_file, O_CREAT | O_RDWR, 0644);
    close(fd);

    ASSERT_EQ(file_get_contents(empty_file), nullptr);
    ASSERT_ERREQ(SW_ERROR_FILE_EMPTY);
    remove(empty_file);

    auto large_file = test::get_root_path() + "/core-tests/bin/core_tests";
    SwooleG.max_file_content = 1024 * 1024;
    ASSERT_EQ(file_get_contents(large_file), nullptr);
    ASSERT_ERREQ(SW_ERROR_FILE_TOO_LARGE);
    SwooleG.max_file_content = SW_MAX_FILE_CONTENT;
}

TEST(file, file_get_size) {
    ASSERT_EQ(file_get_size("/tmp/not-exists-file.txt"), -1);
    ASSERT_ERREQ(ENOENT);

    ASSERT_EQ(file_get_size(9999), -1);
    ASSERT_ERREQ(EBADF);

    int fd = open("/tmp", O_RDONLY);
    ASSERT_EQ(file_get_size(fd), -1);
    ASSERT_ERREQ(EISDIR);
}

TEST(file, open_twice) {
    auto fname = "/tmp/swoole_file_open_twice.txt";
    File file1(fname, File::WRITE | File::CREATE);
    ASSERT_TRUE(file1.ready());

    file1.open(fname, File::READ);
    ASSERT_TRUE(file1.ready());
    file1.close();

    remove(fname);
}

TEST(file, error) {
    Pipe p(true);
    auto buf = sw_tg_buffer();
    File fp(p.get_socket(true)->get_fd());
    ASSERT_EQ(fp.read_all(buf->str, buf->size), 0);
    ASSERT_ERREQ(ESPIPE);

    ASSERT_EQ(fp.write_all(SW_STRL(TEST_STR)), 0);
    ASSERT_ERREQ(ESPIPE);

    p.close();

    FileStatus stat;
    ASSERT_FALSE(fp.stat(&stat));
    ASSERT_ERREQ(EBADF);

    fp.release();
}

TEST(file, tmp_file) {
    char buf[128] = "/tmp/not-exists-dir/test.XXXXXX";
    ASSERT_EQ(swoole_tmpfile(buf), -1);
    ASSERT_ERREQ(ENOENT);
}