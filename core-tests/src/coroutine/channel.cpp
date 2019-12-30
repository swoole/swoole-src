#include "tests.h"

#include "coroutine_channel.h"

using swoole::coroutine::Channel;

using namespace swoole;
using namespace std;

TEST(coroutine_channel, push_pop)
{
    coro_test([](void *arg)
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

    coro_test({
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

    coro_test({
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
    coro_test([](void *arg)
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
    coro_test([](void *arg)
    {
        Channel chan(1);
        void *ret;

        ret = chan.pop(0.001);
        ASSERT_EQ(ret, nullptr);
    });
}
