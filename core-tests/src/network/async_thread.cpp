#include "tests.h"
#include "async.h"

using namespace swoole;

TEST(network_async_thread, thread_one)
{
    int i = 0;
    swAio_event event;
    event.object = &i;
    event.canceled = 0;

    event.handler = [](swAio_event *event)
    {
        (*(int *) event->object)++;
    };

    for (int i = 0; i < 1000; ++i)
    {
        auto ret = swAio_dispatch2(&event);
        ASSERT_EQ(ret->object, event.object);
        ASSERT_NE(ret->task_id, event.task_id);
    }

    ASSERT_EQ(i, 1000);
    swAio_free();
}
