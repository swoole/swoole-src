#include "test_coroutine.h"

using swoole::Coroutine;
using swoole::coroutine::Channel;
using swoole::coroutine::ChannelImpl;

using namespace std;
using namespace swoole::test;

TEST(coroutine_channel, direct_push_pop_data_boundaries) {
    for (auto capacity : {1, 2, 3, 4, 8, 16, 17}) {
        ChannelImpl<int> chan(capacity);

        ASSERT_TRUE(chan.is_empty());
        ASSERT_FALSE(chan.is_full());
        ASSERT_EQ(chan.length(), 0);

        for (int i = 0; i < capacity; i++) {
            ASSERT_TRUE(chan.push_data(i));
            ASSERT_EQ(chan.length(), i + 1);
        }

        ASSERT_TRUE(chan.is_full());
        ASSERT_FALSE(chan.is_empty());
        ASSERT_FALSE(chan.push_data(capacity));
        ASSERT_EQ(chan.get_error(), ChannelImpl<int>::ERROR_TIMEOUT);
        ASSERT_EQ(chan.length(), capacity);

        for (int i = 0; i < capacity; i++) {
            int value = -1;
            ASSERT_TRUE(chan.pop_data(&value));
            ASSERT_EQ(value, i);
            ASSERT_EQ(chan.length(), capacity - i - 1);
        }

        ASSERT_TRUE(chan.is_empty());
        ASSERT_FALSE(chan.is_full());
        int value = -1;
        ASSERT_FALSE(chan.pop_data(&value));
        ASSERT_EQ(value, -1);
    }
}

TEST(coroutine_channel, direct_zero_capacity_uses_one_slot) {
    ChannelImpl<int> chan(0);

    ASSERT_TRUE(chan.push_data(1));
    ASSERT_TRUE(chan.is_full());
    ASSERT_EQ(chan.length(), 1);
    ASSERT_FALSE(chan.push_data(2));

    int value = 0;
    ASSERT_TRUE(chan.pop_data(&value));
    ASSERT_EQ(value, 1);
    ASSERT_TRUE(chan.is_empty());
}

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

TEST(coroutine_channel, cancel) {
    Channel chan(1);

    coroutine::run(
        [](void *arg) {
            auto chan = (Channel *) arg;
            auto cid = Coroutine::create([chan](void *args) {
                ASSERT_EQ(chan->pop(), nullptr);
                ASSERT_EQ(chan->get_error(), Channel::ERROR_CANCELED);
            });

            auto co = Coroutine::get_by_cid(cid);
            ASSERT_TRUE(co->cancel());
            ASSERT_TRUE(chan->close());

            ASSERT_EQ(chan->pop(), nullptr);
            ASSERT_EQ(chan->get_error(), Channel::ERROR_CLOSED);
        },
        &chan);
}
