#include "tests.h"
#include "async.h"

#include <atomic>

using namespace std;

static int callback_count;

static void aio_callback(swAio_event *event)
{
    callback_count++;
}

TEST(aio_thread, dispatch)
{
    atomic<int> handle_count(0);
    swAio_event event;
    event.object = &handle_count;
    event.canceled = 0;
    event.callback = aio_callback;

    callback_count = 0;

    event.handler = [](swAio_event *event)
    {
        (*(atomic<int> *) event->object)++;
    };

    swoole_event_init();
    SwooleTG.reactor->wait_exit = 1;

    for (int i = 0; i < 1000; ++i)
    {
        auto ret = swAio_dispatch2(&event);
        ASSERT_EQ(ret->object, event.object);
        ASSERT_NE(ret->task_id, event.task_id);
    }

    swoole_event_wait();

    ASSERT_EQ(handle_count, 1000);
    ASSERT_EQ(callback_count, 1000);
}
