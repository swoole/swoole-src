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

#include "test_coroutine.h"

using namespace swoole;
using namespace swoole::test;

using swoole::coroutine::Socket;
using swoole::coroutine::System;

static const char *test_file = "/tmp/swoole-core-test";

TEST(coroutine_system, file) {
    test::coroutine::run([](void *arg) {
        char buf[8192];
        size_t n_buf = sizeof(buf);
        ASSERT_EQ(swoole_random_bytes(buf, n_buf), n_buf);
        int flags = 0;
#ifdef O_TMPFILE
        flags |= O_TMPFILE;
#endif
        ASSERT_EQ(System::write_file(test_file, buf, n_buf, true, flags), n_buf);
        swString *data = System::read_file(test_file, true);
        ASSERT_TRUE(data);
        ASSERT_EQ(std::string(buf, n_buf), std::string(data->str, data->length));
        swString_free(data);
        unlink(test_file);
    });
}

