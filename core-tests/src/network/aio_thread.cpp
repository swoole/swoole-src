#include "tests.h"
#ifdef HAVE_SWOOLE_DIR
#include "async.h"
#else
#include "swoole/async.h"
#endif

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
    swAio_event event = {};
    event.object = &handle_count;
    event.callback = aio_callback;

    callback_count = 0;

    event.handler = [](swAio_event *event)
    {
        (*(atomic<int> *) event->object)++;
    };

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    for (int i = 0; i < 1000; ++i)
    {
        auto ret = swAio_dispatch2(&event);
        EXPECT_EQ(ret->object, event.object);
    }

    swoole_event_wait();

    ASSERT_EQ(handle_count, 1000);
    ASSERT_EQ(callback_count, 1000);
}
