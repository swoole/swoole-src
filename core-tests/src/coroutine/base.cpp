#include "tests.h"

using namespace swoole;

TEST(coroutine_base, create)
{
    long _cid;
    long cid = Coroutine::create([](void *arg)
    {
        *(long *) arg = Coroutine::get_current_cid();
    }, &_cid);

    ASSERT_GT(cid, 0);
    ASSERT_EQ(cid, _cid);
}

TEST(coroutine_base, get_current)
{
    long _cid;
    long cid = Coroutine::create([](void *arg)
    {
        auto co = Coroutine::get_current();
        *(long *) arg = co->get_cid();
    }, &_cid);

    ASSERT_GT(cid, 0);
    ASSERT_EQ(cid, _cid);
}

TEST(coroutine_base, yield_resume)
{
    long _cid;
    long cid = Coroutine::create([](void *arg)
    {
        long cid = Coroutine::get_current_cid();
        Coroutine *co = Coroutine::get_by_cid(cid);
        co->yield();
        *(long *) arg = Coroutine::get_current_cid();
    }, &_cid);

    ASSERT_GT(cid, 0);
    Coroutine::get_by_cid(cid)->resume();
    ASSERT_EQ(cid, _cid);
}
