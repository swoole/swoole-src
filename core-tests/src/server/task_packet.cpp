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

#include <fcntl.h>

using swoole::EventData;
using swoole::PacketPtr;
using swoole::PacketTask;
using swoole::Server;
using swoole::String;

TEST(task_packet, inline_lengths_must_fit_storage) {
    EventData task{};
    task.info.len = sizeof(task.data) + 1;
    String buffer(1);
    PacketPtr packet;
    EXPECT_FALSE(Server::task_unpack(&task, &buffer, &packet));

    for (size_t length : {size_t{0}, sizeof(task.data)}) {
        EventData valid{};
        valid.info.len = length;
        memset(valid.data, 'v', sizeof(valid.data));
        ASSERT_TRUE(Server::task_unpack(&valid, &buffer, &packet));
        EXPECT_EQ(packet.length, length);
        EXPECT_EQ(packet.data, valid.data);
        EXPECT_EQ(memcmp(packet.data, valid.data, length), 0);
    }
}

TEST(task_packet, file_header_lengths_must_match) {
    for (size_t length : {size_t{0}, sizeof(PacketTask) - 1, sizeof(PacketTask) + 1}) {
        test::TaskTmpDirectory directory;
        ASSERT_FALSE(directory.path().empty());
        EXPECT_EXIT(
            {
                directory.use_for_tasks();
                EventData task;
                const std::string payload(SW_IPC_MAX_SIZE * 2, 'x');
                if (!Server::task_pack(&task, payload.data(), payload.size())) {
                    _exit(2);
                }
                task.info.len = length;
                String buffer(payload.size());
                PacketPtr packet;
                const bool accepted = Server::task_unpack(&task, &buffer, &packet);
                _exit(!accepted && !directory.empty() ? 0 : 1);
            },
            testing::ExitedWithCode(0),
            "");
    }
}

TEST(task_packet, file_paths_must_have_a_terminator) {
    for (bool terminated : {false, true}) {
        test::TaskTmpDirectory directory;
        ASSERT_FALSE(directory.path().empty());
        EXPECT_EXIT(
            {
                PacketTask file_packet{};
                const size_t capacity = sizeof(file_packet.tmpfile);
                if (capacity <= directory.path().size() + 2) {
                    _exit(2);
                }
                const std::string path =
                    directory.path() + "/" + std::string(capacity - directory.path().size() - 2, 'x');
                int fd = open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
                if (fd < 0 || write(fd, "q", 1) != 1 || close(fd) != 0) {
                    _exit(2);
                }
                memset(file_packet.tmpfile, 'x', capacity);
                memcpy(file_packet.tmpfile, path.data(), path.size());
                if (terminated) {
                    file_packet.tmpfile[capacity - 1] = '\0';
                }
                file_packet.length = 1;
                EventData task{};
                task.info.ext_flags = SW_TASK_TMPFILE;
                task.info.len = sizeof(file_packet);
                memcpy(task.data, &file_packet, sizeof(file_packet));
                String buffer(1);
                PacketPtr packet;
                const bool accepted = Server::task_unpack(&task, &buffer, &packet);
                bool valid;
                if (terminated) {
                    valid = accepted && packet.length == 1 && packet.data[0] == 'q' && directory.empty();
                } else {
                    valid = !accepted && !directory.empty();
                }
                _exit(valid ? 0 : 1);
            },
            testing::ExitedWithCode(0),
            "");
    }
}

TEST(task_packet, valid_file_packets_can_be_peeked_then_consumed) {
    test::TaskTmpDirectory directory;
    ASSERT_FALSE(directory.path().empty());
    EXPECT_EXIT(
        {
            directory.use_for_tasks();
            EventData task;
            const std::string payload(SW_IPC_MAX_SIZE * 2, 'x');
            if (!Server::task_pack(&task, payload.data(), payload.size())) {
                _exit(2);
            }
            task.info.ext_flags |= SW_TASK_PEEK;
            String buffer(payload.size());
            PacketPtr packet;
            bool valid = Server::task_unpack(&task, &buffer, &packet) && packet.length == payload.size() &&
                         memcmp(packet.data, payload.data(), payload.size()) == 0 && !directory.empty();
            task.info.ext_flags &= ~SW_TASK_PEEK;
            valid = valid && Server::task_unpack(&task, &buffer, &packet) && packet.length == payload.size() &&
                    memcmp(packet.data, payload.data(), payload.size()) == 0 && directory.empty();
            _exit(valid ? 0 : 1);
        },
        testing::ExitedWithCode(0),
        "");
}

#endif
