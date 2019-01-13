#include "tests.h"
#include "async.h"

TEST(network_aio_thread, dispatch)
{
    sw_atomic_long_t i = 0;
    swAio_event event;
    event.object = (void *) &i;
    event.canceled = 0;

    event.handler = [](swAio_event *event)
    {
        sw_atomic_fetch_add((sw_atomic_t *) event->object, 1);
    };

    for (int i = 0; i < 1000; ++i)
    {
        auto ret = swAio_dispatch2(&event);
        ASSERT_EQ(ret->object, event.object);
        ASSERT_NE(ret->task_id, event.task_id);
    }

    sleep(1);
    ASSERT_EQ(i, 1000);
    swAio_free();
}
