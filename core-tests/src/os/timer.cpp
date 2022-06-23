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
#include "swoole_util.h"
#include "swoole_timer.h"

using swoole::Timer;
using swoole::TimerNode;

TEST(timer, sys) {
    int timer1_count = 0;
    int timer2_count = 0;
    int timer_running = true;

    uint64_t ms1 = swoole::time<std::chrono::milliseconds>();

    swoole_timer_add(
        20, false, [&](Timer *, TimerNode *) { timer1_count++; }, nullptr);

    swoole_timer_add(
        100,
        true,
        [&](Timer *, TimerNode *tnode) {
            timer2_count++;
            if (timer2_count == 5) {
                swoole_timer_del(tnode);
                timer_running = false;
            }
        },
        nullptr);

    while (1) {
        sleep(10);
        if (SwooleG.signal_alarm) {
            swoole_timer_select();
            if (!timer_running) {
                break;
            }
        }
    }

    uint64_t ms2 = swoole::time<std::chrono::milliseconds>();

    swoole_timer_free();

    ASSERT_LE(ms2 - ms1, 510);
    ASSERT_EQ(timer1_count, 1);
    ASSERT_EQ(timer2_count, 5);
}

TEST(timer, async) {
    int timer1_count = 0;
    int timer2_count = 0;

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    uint64_t ms1 = swoole::time<std::chrono::milliseconds>();
    swoole_timer_after(
        20, [&](Timer *, TimerNode *) { timer1_count++; }, nullptr);

    swoole_timer_tick(
        100,
        [&](Timer *, TimerNode *tnode) {
            timer2_count++;
            if (timer2_count == 5) {
                swoole_timer_del(tnode);
            }
        },
        nullptr);

    swoole_event_wait();
    uint64_t ms2 = swoole::time<std::chrono::milliseconds>();
    ASSERT_LE(ms2 - ms1, 510);
    ASSERT_EQ(timer1_count, 1);
    ASSERT_EQ(timer2_count, 5);
}

TEST(timer, exists) {
    long timer_id = swoole_timer_tick(
        100, [&](Timer *, TimerNode *tnode) {}, nullptr);

    ASSERT_TRUE(swoole_timer_exists(timer_id));
}

TEST(timer, clear) {
    long timer_id = swoole_timer_tick(
        100, [&](Timer *, TimerNode *tnode) {}, nullptr);

    swoole_timer_clear(timer_id);
    ASSERT_FALSE(swoole_timer_exists(timer_id));
}

TEST(timer, get) {
    long timer_id = swoole_timer_tick(
        100, [&](Timer *, TimerNode *tnode) {}, nullptr);

    TimerNode *timerNode = swoole_timer_get(timer_id);
    ASSERT_EQ(timerNode->id, timer_id);
}

TEST(timer, delay) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
    uint64_t ms1 = swoole::time<std::chrono::milliseconds>();
    uint64_t ms2 = 0;
    long timer_id = swoole_timer_after(
        100, [&](Timer *, TimerNode *tnode) { ms2 = swoole::time<std::chrono::milliseconds>(); }, nullptr);

    TimerNode *timerNode = swoole_timer_get(timer_id);
    swoole_timer_delay(timerNode, 100);
    swoole_event_wait();
    ASSERT_GE(ms2 - ms1, 100);
}

TEST(timer, error) {
    Timer *tmp = SwooleTG.timer;
    SwooleTG.timer = nullptr;

    swoole_timer_free();
    ASSERT_EQ(swoole_timer_select(), SW_ERR);
    ASSERT_EQ(swoole_timer_get(1), nullptr);
    ASSERT_FALSE(swoole_timer_clear(1));
    ASSERT_FALSE(swoole_timer_exists(1));

    long timer_id = swoole_timer_tick(
        0, [&](Timer *, TimerNode *tnode) {}, nullptr);
    ASSERT_EQ(timer_id, SW_ERR);

    timer_id = swoole_timer_after(
        0, [&](Timer *, TimerNode *tnode) {}, nullptr);
    ASSERT_EQ(timer_id, SW_ERR);

    swoole_timer_delay(nullptr, 100);
    ASSERT_FALSE(swoole_timer_del(nullptr));
    SwooleTG.timer = tmp;
}
