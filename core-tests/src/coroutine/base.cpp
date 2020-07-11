#include "test_coroutine.h"

using namespace swoole;

TEST(coroutine_base, create) {
    long _cid;
    long cid = Coroutine::create([](void *arg) { *(long *) arg = Coroutine::get_current_cid(); }, &_cid);

    ASSERT_GT(cid, 0);
    ASSERT_EQ(cid, _cid);
}

TEST(coroutine_base, get_current) {
    long _cid;
    long cid = Coroutine::create(
        [](void *arg) {
            auto co = Coroutine::get_current();
            *(long *) arg = co->get_cid();
        },
        &_cid);

    ASSERT_GT(cid, 0);
    ASSERT_EQ(cid, _cid);
}

TEST(coroutine_base, yield_resume) {
    long _cid;
    long cid = Coroutine::create(
        [](void *arg) {
            long cid = Coroutine::get_current_cid();
            Coroutine *co = Coroutine::get_by_cid(cid);
            co->yield();
            *(long *) arg = Coroutine::get_current_cid();
        },
        &_cid);

    ASSERT_GT(cid, 0);
    Coroutine::get_by_cid(cid)->resume();
    ASSERT_EQ(cid, _cid);
}

TEST(coroutine_base, get_cid) {
    Coroutine::create([](void *arg) {
        auto co = Coroutine::get_current();
        long cid = co->get_cid();

        ASSERT_GT(cid, 0);
    });
}

TEST(coroutine_base, get_origin) {
    Coroutine::create([](void *arg) {
        auto *co = Coroutine::get_current();

        Coroutine::create(
            [](void *arg) {
                auto current_co = Coroutine::get_current();
                auto origin_co = current_co->get_origin();

                ASSERT_EQ(arg, origin_co);
            },
            co);
    });
}

TEST(coroutine_base, get_origin_cid) {
    Coroutine::create([](void *arg) {
        auto _cid = Coroutine::get_current_cid();

        Coroutine::create(
            [](void *arg) {
                auto origin_cid = Coroutine::get_current()->get_origin_cid();

                ASSERT_EQ(*(long *) arg, origin_cid);
            },
            &_cid);
    });
}

TEST(coroutine_base, is_end) {
    Coroutine::create([](void *_arg) {
        auto co = Coroutine::get_current();
        ASSERT_FALSE(co->is_end());
    });
}

TEST(coroutine_base, set_task) {
    Coroutine::create([](void *_arg) {
        int task;
        auto co = Coroutine::get_current();
        co->set_task(&task);
        void *actual = co->get_task();
        ASSERT_EQ(actual, &task);
    });
}

TEST(coroutine_base, get_current_task) {
    Coroutine::create([](void *_arg) {
        int task;
        auto co = Coroutine::get_current();
        co->set_task(&task);
        void *actual = co->get_task();
        ASSERT_EQ(actual, Coroutine::get_current_task());
    });
}

TEST(coroutine_base, get_current_cid) {
    Coroutine::create([](void *_arg) {
        auto co = Coroutine::get_current();
        auto actual = co->get_cid();
        ASSERT_EQ(actual, Coroutine::get_current_cid());
    });
}

TEST(coroutine_base, get_by_cid) {
    Coroutine::create([](void *_arg) {
        auto actual = Coroutine::get_current();
        auto cid = actual->get_cid();
        ASSERT_EQ(actual, Coroutine::get_by_cid(cid));
    });
}

TEST(coroutine_base, get_task_by_cid) {
    Coroutine::create([](void *_arg) {
        int task;
        auto co = Coroutine::get_current();
        co->set_task(&task);
        auto actual = co->get_task();
        ASSERT_EQ(actual, Coroutine::get_task_by_cid(co->get_cid()));
    });
}

TEST(coroutine_base, get_last_cid) {
    Coroutine::create([](void *_arg) {});
    Coroutine::create([](void *_arg) {});
    long cid = Coroutine::create([](void *_arg) {});

    ASSERT_EQ(Coroutine::get_last_cid(), cid);
}

TEST(coroutine_base, count) {
    Coroutine::create([](void *_arg) {
        ASSERT_EQ(Coroutine::count(), 1);
        Coroutine::create([](void *_arg) { ASSERT_EQ(Coroutine::count(), 2); });
    });
    ASSERT_EQ(Coroutine::count(), 0);
}

TEST(coroutine_base, get_peak_num) {
    Coroutine::create(
        [](void *_arg) { Coroutine::create([](void *_arg) { ASSERT_GE(Coroutine::get_peak_num(), 2); }); });
}
