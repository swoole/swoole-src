#include "test_coroutine.h"

using swoole::coroutine::Channel;

using namespace std;
using namespace swoole::test;

TEST(coroutine_channel, push_pop)
{
    coroutine::run([](void *arg)
    {
        Channel chan(1);
        int i = 1;
        bool ret;

        ret = chan.push(&i);
        ASSERT_TRUE(ret);
        ASSERT_EQ(*(int *) chan.pop(), i);
    });
}

TEST(coroutine_channel, push_yield)
{
    Channel chan(1);

    coroutine::run({
        make_pair([](void *arg)
        {
            auto chan = (Channel *) arg;
            int i = 1;
            bool ret;

            ret = chan->push(new int(i));
            ASSERT_TRUE(ret);
            ret = chan->push(new int(i));
            ASSERT_TRUE(ret);
        }, &chan),

        make_pair([](void *arg)
        {
            auto chan = (Channel *) arg;
            ASSERT_EQ(*(int *) chan->pop(), 1);
            ASSERT_EQ(*(int *) chan->pop(), 1);
        }, &chan)
    });
}

TEST(coroutine_channel, pop_yield)
{
    Channel chan(1);

    coroutine::run({
        make_pair([](void *arg)
        {
            auto chan = (Channel *) arg;

            ASSERT_EQ(*(int *) chan->pop(), 1);
            ASSERT_EQ(*(int *) chan->pop(), 1);
        }, &chan),

        make_pair([](void *arg)
        {
            auto chan = (Channel *) arg;
            int i = 1;
            bool ret;

            ret = chan->push(&i);
            ASSERT_TRUE(ret);
            ret = chan->push(&i);
            ASSERT_TRUE(ret);
        }, &chan)
    });
}

TEST(coroutine_channel, push_timeout)
{
    coroutine::run([](void *arg)
    {
        Channel chan(1);
        bool ret;

        ret = chan.push(nullptr, 0.001);
        ASSERT_TRUE(ret);
        ret = chan.push(nullptr, 0.001);
        ASSERT_FALSE(ret);
    });
}

TEST(coroutine_channel, pop_timeout)
{
    coroutine::run([](void *arg)
    {
        Channel chan(1);
        void *ret;

        ret = chan.pop(0.001);
        ASSERT_EQ(ret, nullptr);
    });
}
