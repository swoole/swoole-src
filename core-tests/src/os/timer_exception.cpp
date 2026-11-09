#include "test_core.h"
#include "swoole_timer.h"

#include <stdexcept>

using swoole::Timer;
using swoole::TimerNode;

namespace {
void make_due(Timer &timer, TimerNode *node) {
    // A timer cannot run in the round in which it was added.
    timer.select();
    node->exec_msec = 0;
    timer.update(node);
}
}  // namespace

TEST(timer, callback_exception_restores_removal_state) {
    for (bool persistent : {false, true}) {
        SCOPED_TRACE(persistent);
        Timer timer(true);
        unsigned destroyed = 0;
        auto *node = timer.add(
            60000, persistent, nullptr, [](Timer *, TimerNode *) { throw std::runtime_error("timer failed"); });
        ASSERT_NE(node, nullptr);
        const auto id = node->id;
        node->destructor = [&](TimerNode *) { destroyed++; };
        make_due(timer, node);

        EXPECT_THROW(timer.select(), std::runtime_error);
        EXPECT_EQ(timer.get(id), node);
        EXPECT_EQ(destroyed, 0u);
        EXPECT_TRUE(timer.remove(node));
        EXPECT_EQ(timer.get(id), nullptr);
        EXPECT_EQ(timer.count(), 0u);
        EXPECT_EQ(destroyed, 1u);
        // Also release a node left marked for deletion by the unfixed implementation.
        timer.select();

        bool called = false;
        auto *next = timer.add(60000, false, nullptr, [&](Timer *, TimerNode *) { called = true; });
        ASSERT_NE(next, nullptr);
        make_due(timer, next);
        timer.select();
        EXPECT_TRUE(called);
        EXPECT_EQ(timer.count(), 0u);
        EXPECT_EQ(destroyed, 1u);
    }
}

TEST(timer, callback_exception_allows_retry) {
    Timer timer(true);
    unsigned calls = 0;
    auto *node = timer.add(60000, false, nullptr, [&](Timer *, TimerNode *) {
        if (++calls == 1) {
            throw std::runtime_error("retry timer");
        }
    });
    ASSERT_NE(node, nullptr);
    make_due(timer, node);
    EXPECT_THROW(timer.select(), std::runtime_error);
    EXPECT_EQ(calls, 1u);
    EXPECT_EQ(timer.count(), 1u);
    EXPECT_NO_THROW(timer.select());
    EXPECT_EQ(calls, 2u);
    EXPECT_EQ(timer.count(), 0u);
}

TEST(timer, callback_self_removal_preserves_deferred_release) {
    for (bool persistent : {false, true}) {
        for (bool throws : {false, true}) {
            SCOPED_TRACE(persistent);
            SCOPED_TRACE(throws);
            Timer timer(true);
            unsigned destroyed = 0;
            auto *node = timer.add(60000, persistent, nullptr, [&](Timer *owner, TimerNode *current) {
                EXPECT_TRUE(owner->remove(current));
                EXPECT_FALSE(owner->remove(current));
                EXPECT_EQ(owner->get(current->id), current);
                EXPECT_EQ(destroyed, 0u);
                if (throws) {
                    throw std::runtime_error("removed timer");
                }
            });
            ASSERT_NE(node, nullptr);
            node->destructor = [&](TimerNode *) { destroyed++; };
            make_due(timer, node);
            if (throws) {
                EXPECT_THROW(timer.select(), std::runtime_error);
                EXPECT_EQ(destroyed, 0u);
                timer.select();
            } else {
                EXPECT_NO_THROW(timer.select());
            }
            EXPECT_EQ(timer.count(), 0u);
            EXPECT_EQ(destroyed, 1u);
        }
    }
}
