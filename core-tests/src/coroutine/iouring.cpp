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
  | Author: NathanFreeman  <mariasocute@163.com>                         |
  +----------------------------------------------------------------------+
 */

#include <sys/file.h>
#include <sys/stat.h>
#include "test_coroutine.h"
#include "swoole_iouring.h"
#include "swoole_coroutine_c_api.h"

#ifdef SW_USE_IOURING
using swoole::Iouring;
using swoole::Reactor;
using swoole::test::coroutine;

TEST(iouring, create) {
    coroutine::run([](void *arg) {
        SwooleG.iouring_entries = 4;
        SwooleG.iouring_workers = 65536;
        auto fd = Iouring::open(TEST_TMP_FILE, O_CREAT, 0666);
        ASSERT_GE(fd, 0);
        ASSERT_NE(Iouring::close(fd), -1);
    });
}

TEST(iouring, list_all_opcode) {
    auto list = Iouring::list_all_opcode();
    for (auto &item: list) {
        DEBUG() << "opcode: " << item.first << ", value: " << item.second << "\n";
    }
    ASSERT_TRUE(list.size() > 0);
}

TEST(iouring, open_and_close) {
    coroutine::run([](void *arg) {
        const char *test_file = "/tmp/file_1";
        int fd = swoole_coroutine_iouring_open(test_file, O_CREAT, 0666);
        ASSERT_TRUE(fd > 0);

        int result = swoole_coroutine_iouring_close_file(fd);
        ASSERT_TRUE(result == 0);

        result = swoole_coroutine_iouring_unlink(test_file);
        ASSERT_TRUE(result == 0);
    });
}

TEST(iouring, mkdir_and_rmdir) {
    coroutine::run([](void *arg) {
        const char *directory = "/tmp/aaaa";
        int result = swoole_coroutine_iouring_mkdir(directory, 0755);
        ASSERT_TRUE(result == 0);

        result = swoole_coroutine_iouring_rmdir(directory);
        ASSERT_TRUE(result == 0);
    });
}

TEST(iouring, write_and_read) {
    coroutine::run([](void *arg) {
        const char *test_file = "/tmp/file_2";
        int fd = swoole_coroutine_iouring_open(test_file, O_CREAT | O_RDWR, 0666);
        ASSERT_TRUE(fd > 0);

        const char *data = "aaaaaaaaaaaaaaaaaaaaaaa";
        size_t length = strlen(data);
        ssize_t result = swoole_coroutine_iouring_write(fd, (const void *) data, length);
        ASSERT_TRUE(result > 0);
        ASSERT_TRUE(result == static_cast<ssize_t>(length));

        lseek(fd, 0, SEEK_SET);

        char buf[128];
        result = swoole_coroutine_iouring_read(fd, (void *) buf, 128);
        ASSERT_TRUE(result > 0);
        ASSERT_TRUE(result == static_cast<ssize_t>(length));
        buf[result] = '\0';
        ASSERT_STREQ(data, buf);

        result = swoole_coroutine_iouring_close_file(fd);
        ASSERT_TRUE(result == 0);

        result = swoole_coroutine_iouring_unlink(test_file);
        ASSERT_TRUE(result == 0);
    });
}

TEST(iouring, rename) {
    coroutine::run([](void *arg) {
        const char *oldpath = "/tmp/file_2";
        const char *newpath = "/tmp/file_3";
        int fd = swoole_coroutine_iouring_open(oldpath, O_CREAT | O_RDWR, 0666);
        ASSERT_TRUE(fd > 0);

        int result = swoole_coroutine_iouring_close_file(fd);
        ASSERT_TRUE(result == 0);

        result = swoole_coroutine_iouring_rename(oldpath, newpath);
        ASSERT_TRUE(result == 0);

        result = swoole_coroutine_iouring_unlink(newpath);
        ASSERT_TRUE(result == 0);
    });
}

TEST(iouring, fstat_and_stat) {
    coroutine::run([](void *arg) {
        struct stat statbuf {};
        int fd = swoole_coroutine_iouring_open(TEST_TMP_FILE, O_RDWR, 0666);
        ASSERT_TRUE(fd > 0);
        int result = swoole_coroutine_iouring_fstat(fd, &statbuf);
        ASSERT_TRUE(result == 0);
        ASSERT_TRUE(statbuf.st_size > 0);

        result = swoole_coroutine_iouring_close_file(fd);
        ASSERT_TRUE(result == 0);

        statbuf = {};
        result = swoole_coroutine_iouring_stat(TEST_TMP_FILE, &statbuf);
        ASSERT_TRUE(result == 0);
        ASSERT_TRUE(statbuf.st_size > 0);
    });
}

TEST(iouring, fsync_and_fdatasync) {
    coroutine::run([](void *arg) {
        const char *test_file = "/tmp/file_2";
        int fd = swoole_coroutine_iouring_open(test_file, O_CREAT | O_RDWR, 0666);
        ASSERT_TRUE(fd > 0);

        const char *data = "aaaaaaaaaaaaaaaaaaaaaaa";
        size_t length = strlen(data);
        ssize_t write_length = swoole_coroutine_iouring_write(fd, (const void *) data, length);
        ASSERT_TRUE(write_length == static_cast<ssize_t>(length));

        int result = swoole_coroutine_iouring_fsync(fd);
        ASSERT_TRUE(result == 0);

        write_length = swoole_coroutine_iouring_write(fd, (const void *) data, length);
        ASSERT_TRUE(write_length == static_cast<ssize_t>(length));

        result = swoole_coroutine_iouring_fdatasync(fd);
        ASSERT_TRUE(result == 0);

        result = swoole_coroutine_iouring_close_file(fd);
        ASSERT_TRUE(result == 0);

        result = swoole_coroutine_iouring_unlink(test_file);
        ASSERT_TRUE(result == 0);
    });
}
#endif
