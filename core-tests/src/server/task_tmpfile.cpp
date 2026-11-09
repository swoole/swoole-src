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
#include "swoole_string.h"
#ifndef _WIN32
#include "task_tmpdir.h"

#include <sys/resource.h>

using swoole::EventData;
using swoole::PacketPtr;
using swoole::Server;
using swoole::String;

TEST(task_tmpfile, failed_writes_leave_no_files) {
    for (rlim_t bytes : {0u, 16u}) {
        test::TaskTmpDirectory directory;
        ASSERT_FALSE(directory.path().empty());
        EXPECT_EXIT(
            {
                directory.use_for_tasks();
                rlimit original{};
                if (getrlimit(RLIMIT_FSIZE, &original) != 0 || original.rlim_cur < bytes) {
                    _exit(2);
                }
                rlimit limited = original;
                limited.rlim_cur = bytes;
                signal(SIGXFSZ, SIG_IGN);
                if (setrlimit(RLIMIT_FSIZE, &limited) != 0) {
                    _exit(2);
                }
                EventData task;
                const std::string payload(SW_IPC_MAX_SIZE * 2, 'x');
                const bool packed = Server::task_pack(&task, payload.data(), payload.size());
                const int failure_error = errno;
                const bool removed = directory.empty();
                if (setrlimit(RLIMIT_FSIZE, &original) != 0) {
                    _exit(2);
                }
                _exit(!packed && failure_error == EFBIG && removed ? 0 : 1);
            },
            testing::ExitedWithCode(0),
            "");
    }
}

TEST(task_tmpfile, successful_inline_and_file_packets_preserve_bytes) {
    for (size_t length : {0u, 3u, SW_IPC_MAX_SIZE * 2u}) {
        test::TaskTmpDirectory directory;
        ASSERT_FALSE(directory.path().empty());
        EXPECT_EXIT(
            {
                directory.use_for_tasks();
                std::string payload(length, '\0');
                for (size_t i = 0; i < length; i++) {
                    payload[i] = static_cast<char>(i);
                }
                EventData task;
                String buffer(SW_IPC_MAX_SIZE * 2 + 1);
                PacketPtr packet;
                const bool valid = Server::task_pack(&task, payload.data(), payload.size()) &&
                                   Server::task_unpack(&task, &buffer, &packet) && packet.length == payload.size() &&
                                   memcmp(packet.data, payload.data(), payload.size()) == 0 && directory.empty();
                _exit(valid ? 0 : 1);
            },
            testing::ExitedWithCode(0),
            "");
    }
}

TEST(task_tmpfile, creation_failure_preserves_the_error_and_leaves_no_files) {
    test::TaskTmpDirectory directory;
    ASSERT_FALSE(directory.path().empty());
    EXPECT_EXIT(
        {
            SwooleG.task_tmpfile = directory.path() + "/missing/task.XXXXXX";
            EventData task;
            const std::string payload(SW_IPC_MAX_SIZE * 2, 'x');
            const bool packed = Server::task_pack(&task, payload.data(), payload.size());
            const int failure_error = errno;
            _exit(!packed && failure_error == ENOENT && directory.empty() ? 0 : 1);
        },
        testing::ExitedWithCode(0),
        "");
}

#endif
