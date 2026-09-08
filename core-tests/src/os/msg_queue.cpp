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
#include "swoole_msg_queue.h"
#include "swoole_util.h"

#ifdef HAVE_MSGQUEUE
#include <pwd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#endif

using swoole::MsgQueue;
using swoole::QueueNode;

TEST(msg_queue, rbac) {
    MsgQueue q(0x950001);
    ASSERT_TRUE(q.ready());
    ASSERT_GE(q.get_id(), 0);
    QueueNode in;
    in.mtype = 999;
    strcpy(in.mdata, "hello world");

    ASSERT_TRUE(q.set_capacity(8192));

    // input data
    ASSERT_TRUE(q.push(&in, strlen(in.mdata)));

    size_t queue_num, queue_bytes;
    ASSERT_TRUE(q.stat(&queue_num, &queue_bytes));
    ASSERT_EQ(queue_num, 1);
    ASSERT_GT(queue_bytes, 10);

    // output data
    QueueNode out{};
    ASSERT_GT(q.pop(&out, sizeof(out.mdata)), 1);

    ASSERT_TRUE(q.stat(&queue_num, &queue_bytes));
    ASSERT_EQ(queue_num, 0);
    ASSERT_EQ(queue_bytes, 0);

    ASSERT_EQ(out.mtype, in.mtype);
    ASSERT_STREQ(out.mdata, in.mdata);

    ASSERT_TRUE(q.destroy());
    ASSERT_FALSE(q.destroy());
    ASSERT_ERREQ(EINVAL);

    q.set_blocking(false);

    ASSERT_EQ(q.pop(&out, sizeof(out.mdata)), -1);
    ASSERT_ERREQ(EINVAL);

    ASSERT_FALSE(q.push(&in, strlen(in.mdata)));
    ASSERT_ERREQ(EINVAL);

    ASSERT_FALSE(q.stat(&queue_num, &queue_bytes));
    ASSERT_ERREQ(EINVAL);

    ASSERT_FALSE(q.set_capacity(8192));
    ASSERT_ERREQ(EINVAL);
}

#ifdef HAVE_MSGQUEUE
static key_t make_queue_key(int line) {
    return 0x69000000 + ((getpid() + line) & 0xfffff);
}

TEST(msg_queue, set_access_preserves_trusted_backlog) {
    MsgQueue q(make_queue_key(__LINE__), true, 0644);
    ASSERT_TRUE(q.ready());
    ON_SCOPE_EXIT {
        q.destroy();
    };

    QueueNode in{};
    in.mtype = 1;
    strcpy(in.mdata, "pending");
    ASSERT_TRUE(q.push(&in, strlen(in.mdata)));
    ASSERT_TRUE(q.set_access(geteuid(), getegid(), 0600));

    msqid_ds status;
    ASSERT_EQ(msgctl(q.get_id(), IPC_STAT, &status), 0);
    ASSERT_EQ(status.msg_perm.uid, geteuid());
    ASSERT_EQ(status.msg_perm.gid, getegid());
    ASSERT_EQ(status.msg_perm.mode & 0777, 0600);
    ASSERT_EQ(status.msg_qnum, 1);

    QueueNode out{};
    out.mtype = 1;
    ASSERT_GT(q.pop(&out, sizeof(out.mdata)), 0);
    ASSERT_STREQ(out.mdata, in.mdata);
}

TEST(msg_queue, set_access_replaces_writable_backlog) {
    MsgQueue q(make_queue_key(__LINE__), true, 0666);
    ASSERT_TRUE(q.ready());
    ON_SCOPE_EXIT {
        q.destroy();
    };

    QueueNode in{};
    in.mtype = 1;
    strcpy(in.mdata, "pending");
    ASSERT_TRUE(q.push(&in, strlen(in.mdata)));
    ASSERT_TRUE(q.set_access(geteuid(), getegid(), 0600));

    msqid_ds status;
    ASSERT_EQ(msgctl(q.get_id(), IPC_STAT, &status), 0);
    ASSERT_EQ(status.msg_perm.mode & 0777, 0600);
    ASSERT_EQ(status.msg_qnum, 0);

    q.set_blocking(false);
    QueueNode out{};
    out.mtype = 1;
    ASSERT_EQ(q.pop(&out, sizeof(out.mdata)), -1);
    ASSERT_ERREQ(ENOMSG);
}

TEST(msg_queue, set_access_changes_private_queue_owner) {
    if (geteuid() != 0) {
        GTEST_SKIP();
    }
    auto *passwd = getpwnam("nobody");
    if (passwd == nullptr) {
        GTEST_SKIP();
    }

    MsgQueue q(IPC_PRIVATE, true, 0600);
    ASSERT_TRUE(q.ready());
    ON_SCOPE_EXIT {
        q.destroy();
    };
    ASSERT_TRUE(q.set_access(passwd->pw_uid, passwd->pw_gid, 0600));

    msqid_ds status;
    ASSERT_EQ(msgctl(q.get_id(), IPC_STAT, &status), 0);
    ASSERT_EQ(status.msg_perm.uid, passwd->pw_uid);
    ASSERT_EQ(status.msg_perm.gid, passwd->pw_gid);
    ASSERT_EQ(status.msg_perm.mode & 0777, 0600);
}

TEST(msg_queue, set_access_rejects_forged_owner) {
    key_t key = make_queue_key(__LINE__);
    uid_t target_uid = geteuid() == 0 ? 0 : geteuid() + 1;
    ON_SCOPE_EXIT {
        int msg_id = msgget(key, 0);
        if (msg_id >= 0) {
            msgctl(msg_id, IPC_RMID, nullptr);
        }
    };

    if (geteuid() == 0) {
        pid_t pid = fork();
        ASSERT_GE(pid, 0);
        if (pid == 0) {
            if (setgid(65534) < 0 || setuid(65534) < 0) {
                _exit(1);
            }
            MsgQueue q(key, true, 0666);
            QueueNode in{};
            in.mtype = 1;
            strcpy(in.mdata, "pending");
            if (!q.ready() || !q.push(&in, strlen(in.mdata))) {
                _exit(2);
            }
            msqid_ds status;
            if (msgctl(q.get_id(), IPC_STAT, &status) < 0) {
                _exit(3);
            }
            status.msg_perm.uid = target_uid;
            status.msg_perm.mode = 0600;
            _exit(msgctl(q.get_id(), IPC_SET, &status) < 0 ? 4 : 0);
        }
        int status;
        ASSERT_EQ(waitpid(pid, &status, 0), pid);
        ASSERT_TRUE(WIFEXITED(status));
        ASSERT_EQ(WEXITSTATUS(status), 0);
    } else {
        MsgQueue attacker(key, true, 0666);
        ASSERT_TRUE(attacker.ready());
        QueueNode in{};
        in.mtype = 1;
        strcpy(in.mdata, "pending");
        ASSERT_TRUE(attacker.push(&in, strlen(in.mdata)));
        msqid_ds status;
        ASSERT_EQ(msgctl(attacker.get_id(), IPC_STAT, &status), 0);
        status.msg_perm.uid = target_uid;
        status.msg_perm.mode = 0600;
        ASSERT_EQ(msgctl(attacker.get_id(), IPC_SET, &status), 0);
    }

    MsgQueue q(key, true, 0600);
    ASSERT_TRUE(q.ready());
    ASSERT_TRUE(q.set_access(target_uid, getegid(), 0600));

    msqid_ds status;
    ASSERT_EQ(msgctl(q.get_id(), IPC_STAT, &status), 0);
    ASSERT_EQ(status.msg_perm.uid, target_uid);
    ASSERT_EQ(status.msg_perm.mode & 0777, 0600);
    ASSERT_EQ(status.msg_qnum, 0);
}
#endif
