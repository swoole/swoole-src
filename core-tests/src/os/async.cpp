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

#include "swoole_socket.h"
#include "swoole_async.h"

#include <atomic>

using namespace swoole;

static int callback_count;

TEST(async, dispatch) {
    callback_count = 0;
    std::atomic<int> handle_count(0);
    AsyncEvent event = {};
    event.object = &handle_count;
    event.callback = [](AsyncEvent *event) { callback_count++; };
    event.handler = [](AsyncEvent *event) { (*(std::atomic<int> *) event->object)++; };

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    for (int i = 0; i < 1000; ++i) {
        auto ret = swoole::async::dispatch(&event);
        EXPECT_EQ(ret->object, event.object);
    }

    swoole_event_wait();

    ASSERT_EQ(handle_count, 1000);
    ASSERT_EQ(callback_count, 1000);
}

TEST(async, schedule) {
    callback_count = 0;
    std::atomic<int> handle_count(0);

    int N = 1000;

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    AsyncEvent event{};
    event.object = &handle_count;
    event.callback = [](AsyncEvent *event) { callback_count++; };
    event.handler = [](AsyncEvent *event) {
        usleep(swoole_rand(50000, 100000));
        (*(std::atomic<int> *) event->object)++;
    };

    SwooleG.aio_core_worker_num = 4;
    SwooleG.aio_worker_num = 128;
    SwooleG.aio_max_wait_time = 0.05;
    SwooleG.aio_max_idle_time = 0.5;

    int count = N;
    swoole_timer_tick(2, [&count, &event, N](Timer *, TimerNode *timer) {
        SW_LOOP_N(swoole_rand(5, 15)) {
            auto ret = swoole::async::dispatch(&event);
            EXPECT_EQ(ret->object, event.object);
            count--;
            if (count == 0) {
                swoole_timer_del(timer);
                ASSERT_EQ(SwooleTG.async_threads->get_worker_num(), 128);
                ASSERT_GT(SwooleTG.async_threads->get_queue_size(), 100);
                ASSERT_GT(SwooleTG.async_threads->get_task_num(), 100);
                break;
            }
        }
    });

    swoole_event_wait();

    ASSERT_EQ(handle_count, N);
    ASSERT_EQ(callback_count, N);
}
