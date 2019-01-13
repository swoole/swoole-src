#include "tests.h"
#include "channel.h"

using namespace swoole;

TEST(coroutine_channel, push_pop)
{
    // can't use coro_test because it will stop at reactor->wait
    Coroutine::create([](void *arg)
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

    Coroutine::create([](void *arg)
    {
        auto chan = (Channel *) arg;
        int i = 1;
        bool ret;

        ret = chan->push(&i);
        ASSERT_TRUE(ret);
        ret = chan->push(&i);
        ASSERT_TRUE(ret);
    }, &chan);

    Coroutine::create([](void *arg)
    {
        auto chan = (Channel *) arg;
        ASSERT_EQ(*(int *) chan->pop(), 1);
        ASSERT_EQ(*(int *) chan->pop(), 1);
    }, &chan);
}

TEST(coroutine_channel, pop_yield)
{
    Channel chan(1);

    Coroutine::create([](void *arg)
    {
        auto chan = (Channel *) arg;

        ASSERT_EQ(*(int *) chan->pop(), 1);
        ASSERT_EQ(*(int *) chan->pop(), 1);
    }, &chan);

    Coroutine::create([](void *arg)
    {
        auto chan = (Channel *) arg;
        int i = 1;
        bool ret;

        ret = chan->push(&i);
        ASSERT_TRUE(ret);
        ret = chan->push(&i);
        ASSERT_TRUE(ret);
    }, &chan);
}

TEST(coroutine_channel, push_timeout)
{
    Coroutine::create([](void *arg)
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
    Coroutine::create([](void *arg)
    {
        Channel chan(1);
        void *ret;

        ret = chan.pop(0.001);
        ASSERT_EQ(ret, nullptr);
    });
}
