#include "tests.h"

TEST(coroutine_channel, push_pop)
{
    coro_test([](void *arg)
    {
        Channel chan(1);
        int i = 1;
        chan->push(&i);
        ASSERT_EQ(*chan->pop(), i);
    });
}

TEST(coroutine_channel, push_yield)
{
    coro_test([](void *arg)
    {
        Channel chan(1);
        int i = 1;
        chan->push(&i);
        ASSERT_EQ(*chan->pop(), i);
    });
}

TEST(coroutine_channel, pop_yield)
{
    coro_test([](void *arg)
    {
        Channel chan(1);
        int i = 1;
        chan->push(&i);
        ASSERT_EQ(*chan->pop(), i);
    });
}
