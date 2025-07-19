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
#include "swoole_file.h"

using namespace std;
using namespace swoole;
using swoole::coroutine::System;

TEST(coroutine_async_file, async_file) {
    coroutine::run([](void *arg) {
        string filename = "/tmp/file.txt";
        auto file = new AsyncFile(filename, O_CREAT | O_RDWR, 0666);
        ON_SCOPE_EXIT {
           delete file;
        };
        ASSERT_EQ(file->ready(), true);
        ASSERT_EQ(file->truncate(0), true);
        ASSERT_EQ(file->set_offset(0), 0);
        ASSERT_EQ(file->get_offset(), 0);

        const char *data = "Hello World!";
        size_t length = strlen(data);
        ASSERT_EQ(file->write((void *) data, length), static_cast<ssize_t>(length));

        ASSERT_EQ(file->sync(), true);
        ASSERT_EQ(file->set_offset(0), 0);

        char buf[1024];
        ASSERT_EQ(file->read((void *) buf, 1024), static_cast<ssize_t>(length));
        buf[length] = '\0';
        ASSERT_STREQ(data, buf);

        struct stat statbuf {};
        ASSERT_EQ(file->stat(&statbuf), true);
        ASSERT_TRUE(statbuf.st_size > 0);
    });
}
