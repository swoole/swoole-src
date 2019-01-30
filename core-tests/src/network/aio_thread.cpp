#include "tests.h"
#include "async.h"

#include <atomic>

using namespace std;

TEST(network_aio_thread, dispatch)
{
    atomic<int> i(0);
    swAio_event event;
    event.object = &i;
    event.canceled = 0;

    event.handler = [](swAio_event *event)
    {
        (*(atomic<int> *) event->object)++;
    };

    for (int i = 0; i < 1000; ++i)
    {
        swAio_event *event_copy;
        swAio_dispatch_ex(&event, &event_copy);
        ASSERT_EQ(event_copy->object, event.object);
        ASSERT_NE(event_copy->task_id, event.task_id);
    }

    time_t start = time(nullptr);
    while (i != 1000)
    {
        usleep(100);
        
        if ((time(nullptr) - start) > 3)
        {
            ASSERT_TRUE(false);
        }
    }

    swAio_free();
}
