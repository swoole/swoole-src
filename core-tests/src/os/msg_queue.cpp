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
