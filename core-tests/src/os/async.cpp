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
    int count = 1000;
    callback_count = 0;
    std::atomic<int> handle_count(0);
    AsyncEvent event = {};
    event.object = &handle_count;
    event.callback = [](AsyncEvent *event) { callback_count++; };
    event.handler = [](AsyncEvent *event) { ++(*static_cast<std::atomic<int> *>(event->object)); };

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    for (int i = 0; i < count; ++i) {
        auto ret = swoole::async::dispatch(&event);
        EXPECT_EQ(ret->object, event.object);
    }

    swoole_event_wait();

    ASSERT_EQ(handle_count, count);
    ASSERT_EQ(callback_count, count);
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
        ++(*static_cast<std::atomic<int> *>(event->object));
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
                ASSERT_GT(sw_async_threads()->get_worker_num(), 16);
                ASSERT_GT(sw_async_threads()->get_queue_size(), 100);
                ASSERT_GT(sw_async_threads()->get_task_num(), 100);
                break;
            } else if (count == N - 1) {
                ASSERT_EQ(sw_async_threads()->get_worker_num(), 4);
                ASSERT_LE(sw_async_threads()->get_queue_size(), 1);
                ASSERT_EQ(sw_async_threads()->get_task_num(), 1);
            } else if (count < N / 2) {
                ASSERT_GT(sw_async_threads()->get_worker_num(), 4);
            }
        }

        if (count % 50 == 0) {
            DEBUG() << "async worker thread num=" << sw_async_threads()->get_worker_num() << "\n";
        }
    });

    swoole_timer_tick(2000, [](TIMER_PARAMS) {
        DEBUG() << "async worker thread num=" << sw_async_threads()->get_worker_num() << "\n";
        if (sw_async_threads()->get_worker_num() < 16) {
            swoole_timer_del(tnode);
        }
    });

    swoole_event_wait();

    ASSERT_EQ(handle_count, N);
    ASSERT_EQ(callback_count, N);
}

TEST(async, misc) {
    callback_count = 0;
    std::atomic<int> handle_count(0);
    AsyncEvent event = {};
    AsyncEvent *rv;
    event.object = &handle_count;
    event.callback = [](AsyncEvent *event) { callback_count++; };
    event.handler = [](AsyncEvent *event) { ++(*static_cast<std::atomic<int> *>(event->object)); };

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    auto ret = swoole::async::dispatch(&event);
    EXPECT_EQ(ret->object, event.object);

    sw_async_threads()->notify_one();

    AsyncEvent event2 = {};
    event2.callback = [](AsyncEvent *event) {
        ASSERT_EQ(event->retval, -1);
        ASSERT_EQ(event->error, SW_ERROR_AIO_BAD_REQUEST);
        callback_count++;
    };
    rv = swoole::async::dispatch(&event2);
    EXPECT_NE(rv, nullptr);

    swoole_event_wait();

    ASSERT_EQ(handle_count, 1);
    ASSERT_EQ(callback_count, 2);
}
