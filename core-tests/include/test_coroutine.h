#pragma once

#include "test_core.h"

#ifdef HAVE_SWOOLE_DIR
#include "coroutine.h"
#include "coroutine_channel.h"
#include "coroutine_system.h"
#include "coroutine_socket.h"
#include "coroutine_c_api.h"
#else
#include "swoole/coroutine.h"
#include "swoole/coroutine_channel.h"
#include "swoole/coroutine_system.h"
#include "swoole/coroutine_socket.h"
#include "swoole/coroutine_c_api.h"
#endif

namespace swoole { namespace test {

class coroutine
{
public:
    coroutine(const coroutine_func_t &_fn, void *_arg, int *_complete_num) :
            fn(_fn), arg(_arg), complete_num(_complete_num) { }

    void start()
    {
        fn(arg);
        (*complete_num)++;
    }

    inline static void create(const coroutine_func_t &fn, void *arg, int *complete_num)
    {
        auto test = new coroutine(fn, arg, complete_num);

        long cid = swoole::Coroutine::create([](void *arg)
        {
            ((coroutine *) arg)->start();
            delete (coroutine *) arg;
        }, test);
        ASSERT_GT(cid, 0);
    }

    inline static void run(std::initializer_list<std::pair<coroutine_func_t, void*>> args)
    {
        int complete_num = 0;
        swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
        for (const auto &arg : args)
        {
            create(arg.first, arg.second, &complete_num);
        }
        swoole_event_wait();
    }

    inline static void run(std::initializer_list<coroutine_func_t> fns)
    {
        int complete_num = 0;
        swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
        for (const auto &fn : fns)
        {
            create(fn, nullptr, &complete_num);
        }
        swoole_event_wait();
    }

    inline static void run(const coroutine_func_t &fn, void *arg = nullptr)
    {
        int complete_num = 0;
        swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
        create(fn, arg, &complete_num);
        swoole_event_wait();
    }

private:
    coroutine_func_t fn;
    void *arg;
    int *complete_num;
};
}
}


