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
#include "swoole_signal.h"
#include "swoole_util.h"
#include "swoole_timer.h"

#include <stdexcept>

using swoole::Timer;
using swoole::TimerNode;

TEST(timer, callback_copy_failure_preserves_existing_timers) {
    struct Callback {
        bool &fail_copy;
        explicit Callback(bool &fail) : fail_copy(fail) {}
        Callback(const Callback &other) : fail_copy(other.fail_copy) {
            if (fail_copy) {
                throw std::runtime_error("timer callback copy failed");
            }
        }
        void operator()(Timer *, TimerNode *) const {}
    };

    bool fail_copy = false;
    swoole::TimerCallback callback = Callback(fail_copy);
    Timer timer(true);
    auto *existing = timer.add(60000, false, nullptr, callback);
    ASSERT_NE(existing, nullptr);
    const auto existing_id = existing->id;

    fail_copy = true;
    EXPECT_THROW(timer.add(1, false, nullptr, callback), std::runtime_error);
    EXPECT_EQ(timer.count(), 1);
    EXPECT_EQ(timer.get(existing_id), existing);
    EXPECT_EQ(timer.get_next_msec(), 60000);

    fail_copy = false;
    auto *next = timer.add(1, false, nullptr, callback);
    ASSERT_NE(next, nullptr);
    EXPECT_TRUE(timer.remove(next));
    EXPECT_TRUE(timer.remove(existing));
    timer.select();
    EXPECT_EQ(timer.count(), 0);
    EXPECT_EQ(timer.get_next_msec(), -1);
}

TEST(timer, sys) {
    swoole::test::counter_init();
    auto counter = swoole::test::counter_ptr();

    uint64_t ms1 = swoole::time<std::chrono::milliseconds>();

    ASSERT_TRUE(swoole_timer_add(
        20L, false, [&](TIMER_PARAMS) { counter[0]++; }, nullptr));

    swoole_clear_last_error();
    ASSERT_EQ(swoole_timer_add(-1L, false, [&](TIMER_PARAMS) {}), nullptr);
    ASSERT_ERREQ(SW_ERROR_INVALID_PARAMS);

    swoole_clear_last_error();
    ASSERT_EQ(swoole_timer_add(0L, false, [&](TIMER_PARAMS) {}), nullptr);
    ASSERT_ERREQ(SW_ERROR_INVALID_PARAMS);

    // dtor test
    auto timer = swoole_timer_add(20L, false, [&](TIMER_PARAMS) { counter[2]++; }, counter);
    ASSERT_TRUE(timer);
    timer->type = TimerNode::TYPE_USER;
    auto previous_destructor =
        Timer::set_user_destructor([](TimerNode *tnode) { static_cast<int *>(tnode->data)[3] = 9999; });
    ON_SCOPE_EXIT {
        Timer::set_user_destructor(previous_destructor);
    };

    swoole_timer_add(
        100L,
        true,
        [&](Timer *, TimerNode *tnode) {
            counter[1]++;
            if (counter[1] == 5) {
                swoole_timer_del(tnode);
            }
        },
        nullptr);

    while (sw_timer()->count() > 0) {
        sleep(10);
        swoole_signal_dispatch();
        if (SwooleG.signal_alarm) {
            swoole_timer_select();
        }
    }

    uint64_t ms2 = swoole::time<std::chrono::milliseconds>();

    swoole_timer_free();

    ASSERT_LE(ms2 - ms1, 510);
    ASSERT_EQ(counter[0], 1);
    ASSERT_EQ(counter[1], 5);
    ASSERT_EQ(counter[2], 1);
    ASSERT_EQ(counter[3], 9999);
}

TEST(timer, destructor_dispatch) {
    int destroyed[3] = {};
    int kernel_data = 7;
    int callbacks = 0;
    auto previous_destructor = Timer::set_user_destructor([](TimerNode *tnode) { ++*static_cast<int *>(tnode->data); });
    ON_SCOPE_EXIT {
        Timer::set_user_destructor(previous_destructor);
    };
    {
        Timer timer(true);
        TimerNode *user_nodes[3];
        TimerNode *kernel_nodes[3];
        auto callback = [&](Timer *, TimerNode *) { callbacks++; };
        for (int i = 0; i < 3; i++) {
            user_nodes[i] = timer.add(60000, false, &destroyed[i], callback);
            ASSERT_NE(user_nodes[i], nullptr);
            user_nodes[i]->type = TimerNode::TYPE_USER;
            kernel_nodes[i] = timer.add(60000, false, &kernel_data, callback);
            ASSERT_NE(kernel_nodes[i], nullptr);
        }

        ASSERT_TRUE(timer.remove(user_nodes[0]));
        ASSERT_TRUE(timer.remove(kernel_nodes[0]));
        EXPECT_EQ(destroyed[0], 1);
        EXPECT_EQ(callbacks, 0);

        user_nodes[1]->exec_msec = 0;
        timer.update(user_nodes[1]);
        kernel_nodes[1]->exec_msec = 0;
        timer.update(kernel_nodes[1]);
        timer.select();
        EXPECT_EQ(destroyed[1], 1);
        EXPECT_EQ(destroyed[2], 0);
        EXPECT_EQ(callbacks, 2);
        EXPECT_EQ(timer.count(), 2);
    }
    EXPECT_EQ(destroyed[0], 1);
    EXPECT_EQ(destroyed[1], 1);
    EXPECT_EQ(destroyed[2], 1);
    EXPECT_EQ(kernel_data, 7);

    int other_destroyed = 0;
    {
        Timer other_timer(true);
        auto *node = other_timer.add(60000, false, &other_destroyed, [](Timer *, TimerNode *) {});
        ASSERT_NE(node, nullptr);
        node->type = TimerNode::TYPE_USER;
    }
    EXPECT_EQ(other_destroyed, 1);
}

TEST(timer, user_timer_default_destructor) {
    auto previous_destructor = Timer::set_user_destructor(nullptr);
    ON_SCOPE_EXIT {
        Timer::set_user_destructor(previous_destructor);
    };
    EXPECT_NE(previous_destructor, nullptr);
    int data = 7;
    Timer timer(true);
    auto *node = timer.add(60000, false, &data, [](Timer *, TimerNode *) {});
    ASSERT_NE(node, nullptr);
    node->type = TimerNode::TYPE_USER;
    EXPECT_TRUE(timer.remove(node));
    EXPECT_EQ(data, 7);
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
    swoole_timer_free();
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
    swoole_timer_del(timerNode);
    swoole_timer_free();
}

TEST(timer, error) {
    Timer *tmp = SwooleTG.timer;
    SwooleTG.timer = nullptr;

    swoole_timer_free();
    swoole_timer_select();  // no effect
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

    swoole_timer_free();
}

TEST(timer, reinit) {
    int timer1_count = 0;
    int timer2_count = 0;

    swoole_timer_after(
        20,
        [&](Timer *, TimerNode *) {
            timer1_count++;
            DEBUG() << "timer2_count" << timer2_count << "\n";
        },
        nullptr);

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    sw_timer()->reinit();

    uint64_t ms1 = swoole::time<std::chrono::milliseconds>();

    swoole_timer_tick(
        100,
        [&](Timer *, TimerNode *tnode) {
            timer2_count++;
            DEBUG() << "timer2_count" << timer2_count << "\n";
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

TEST(timer, realtime_add) {
	timespec ts;
	ts.tv_sec = 1;
	ts.tv_nsec = 900L * SW_NUM_MILLION;

	swoole::realtime_add(&ts, 1905);
	ASSERT_EQ(ts.tv_sec, 3);
	ASSERT_EQ(ts.tv_nsec, 805L * SW_NUM_MILLION);
}

TEST(timer, reactor_round) {
    ASSERT_EQ(swoole_event_init(0), SW_OK);
    int count = 0;
    auto *node = swoole_timer_add(1L, false, [&](TIMER_PARAMS) { count++; });
    ASSERT_NE(node, nullptr);
    node->exec_msec = 0;
    sw_timer()->update(node);

    // Selection cannot advance the event loop's round.
    sw_timer()->select();
    EXPECT_EQ(count, 0);
    sw_timer()->select();
    EXPECT_EQ(count, 0);
    EXPECT_EQ(sw_timer()->get_round(), 0);
    sw_reactor()->execute_end_callbacks();
    EXPECT_EQ(sw_timer()->get_round(), 1);
    sw_timer()->select();
    EXPECT_EQ(count, 1);
    swoole_event_free();
}

TEST(timer, reactor_reinit_manual_round) {
    ASSERT_EQ(swoole_event_init(0), SW_OK);
    int count = 0;
    auto *node = swoole_timer_add(1L, false, [&](TIMER_PARAMS) { count++; });
    ASSERT_NE(node, nullptr);
    node->exec_msec = 0;
    sw_timer()->update(node);

    sw_reactor()->execute_end_callbacks();
    EXPECT_EQ(sw_timer()->get_round(), 1);
    sw_timer()->reinit(true);
    EXPECT_EQ(sw_timer()->get_round(), 0);
    EXPECT_EQ(sw_timer()->get_reactor(), nullptr);
    sw_timer()->select();
    EXPECT_EQ(count, 1);
    EXPECT_EQ(sw_timer()->get_round(), 0);
    EXPECT_EQ(sw_reactor()->get_round(), 1);
    swoole_event_free();
}
