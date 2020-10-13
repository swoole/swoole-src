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
#include "swoole_msg_queue.h"

TEST(msg_queue, rbac) {
    swMsgQueue q;
    ASSERT_EQ(swMsgQueue_create(&q, 0, 0, 0), SW_OK);
    swQueue_data in;
    in.mtype = 999;
    strcpy(in.mdata, "hello world");

    ASSERT_EQ(swMsgQueue_push(&q, &in, strlen(in.mdata)), SW_OK);

    size_t queue_num, queue_bytes;
    ASSERT_EQ(swMsgQueue_stat(&q, &queue_num, &queue_bytes), SW_OK);
    ASSERT_EQ(queue_num, 1);
    ASSERT_GT(queue_bytes, 10);

    swQueue_data out = {};
    ASSERT_GT(swMsgQueue_pop(&q, &out, sizeof(out)), 1);

    ASSERT_EQ(out.mtype, in.mtype);
    ASSERT_STREQ(out.mdata, in.mdata);
}
