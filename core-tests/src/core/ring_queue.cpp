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
#include "ring_queue.h"

using swoole::RingQueue;

TEST(ring_queue, push_pop) {
    RingQueue<int> queue(5);
    ASSERT_EQ(0, queue.count());
    for (int i = 0; i < 5; i++) {
        queue.push(i);
    }
    ASSERT_EQ(5, queue.count());
    for (int i = 0; i < 5; i++) {
        ASSERT_EQ(i, queue.pop());
    }
    ASSERT_TRUE(queue.empty());
}
