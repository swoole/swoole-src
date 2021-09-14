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
#include "swoole_pipe.h"

using namespace swoole;

TEST(defer_task, defer) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
    Reactor *reactor = sw_reactor();
    ASSERT_EQ(reactor->max_event_num, SW_REACTOR_MAXEVENTS);

    int count = 0;
    reactor->defer([&count](void *) { count++; });
    swoole_event_wait();
    ASSERT_EQ(count, 1);
    swoole_event_free();
}

TEST(defer_task, cancel_1) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
    Reactor *reactor = sw_reactor();
    ASSERT_EQ(reactor->max_event_num, SW_REACTOR_MAXEVENTS);

    int count = 0;
    reactor->defer([&count](void *) { count += 2; });
    auto iter = reactor->get_last_defer_task();
    reactor->remove_defer_task(iter);

    reactor->defer([&count](void *) { count += 5; });

    swoole_event_wait();
    ASSERT_EQ(count, 5);
    swoole_event_free();
}

TEST(defer_task, cancel_2) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
    Reactor *reactor = sw_reactor();
    ASSERT_EQ(reactor->max_event_num, SW_REACTOR_MAXEVENTS);

    int count = 0;
    reactor->defer([&count](void *) { count += 2; });
    auto iter = reactor->get_last_defer_task();
    reactor->remove_defer_task(iter);

    swoole_event_wait();
    ASSERT_EQ(count, 0);
    swoole_event_free();
}
