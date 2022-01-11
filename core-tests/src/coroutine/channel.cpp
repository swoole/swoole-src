#include "test_coroutine.h"

using swoole::coroutine::Channel;

using namespace std;
using namespace swoole::test;

TEST(coroutine_channel, push_pop) {
    coroutine::run([](void *arg) {
        Channel chan(1);
        int i = 1;
        bool ret;

        ret = chan.push(&i);
        ASSERT_TRUE(ret);
        ASSERT_EQ(*(int *) chan.pop(), i);
    });
}

TEST(coroutine_channel, push_yield) {
    Channel chan(1);

    coroutine::run({make_pair(
                        [](void *arg) {
                            auto chan = (Channel *) arg;
                            int i = 1;
                            bool ret;

                            ret = chan->push(new int(i));
                            ASSERT_TRUE(ret);
                            ret = chan->push(new int(i));
                            ASSERT_TRUE(ret);
                        },
                        &chan),

                    make_pair(
                        [](void *arg) {
                            auto chan = (Channel *) arg;
                            ASSERT_EQ(*(int *) chan->pop(), 1);
                            ASSERT_EQ(*(int *) chan->pop(), 1);
                        },
                        &chan)});
}

TEST(coroutine_channel, pop_yield) {
    Channel chan(1);

    coroutine::run({make_pair(
                        [](void *arg) {
                            auto chan = (Channel *) arg;

                            ASSERT_EQ(*(int *) chan->pop(), 1);
                            ASSERT_EQ(*(int *) chan->pop(), 1);
                        },
                        &chan),

                    make_pair(
                        [](void *arg) {
                            auto chan = (Channel *) arg;
                            int i = 1;
                            bool ret;

                            ret = chan->push(&i);
                            ASSERT_TRUE(ret);
                            ret = chan->push(&i);
                            ASSERT_TRUE(ret);
                        },
                        &chan)});
}

TEST(coroutine_channel, push_timeout) {
    coroutine::run([](void *arg) {
        Channel chan(1);
        bool ret;

        ret = chan.push(nullptr, 0.001);
        ASSERT_TRUE(ret);
        ret = chan.push(nullptr, 0.001);
        ASSERT_FALSE(ret);
    });
}

TEST(coroutine_channel, pop_timeout) {
    coroutine::run([](void *arg) {
        Channel chan(1);
        void *ret;

        ret = chan.pop(0.001);
        ASSERT_EQ(ret, nullptr);
    });
}

TEST(coroutine_channel, close) {
    Channel chan(1);
    coroutine::run(
        [](void *arg) {
            int value = 1;
            auto chan = (Channel *) arg;
            while (1) {
                if (!chan->push((void *) &value)) {
                    ASSERT_EQ(chan->get_error(), Channel::ErrorCode::ERROR_CLOSED);
                    ASSERT_FALSE(chan->push(nullptr));
                    break;
                }
            }
        },
        &chan);

    ASSERT_TRUE(chan.close());
    ASSERT_FALSE(chan.close());

    Channel chan2(1);
    coroutine::run(
        [](void *arg) {
            auto chan = (Channel *) arg;
            while (1) {
                if (!chan->pop(0)) {
                    ASSERT_EQ(chan->get_error(), Channel::ErrorCode::ERROR_CLOSED);
                    ASSERT_EQ(chan->pop(), nullptr);
                    break;
                }
            }
        },
        &chan2);

    ASSERT_TRUE(chan2.close());
}
