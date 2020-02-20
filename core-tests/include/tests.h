#pragma once

#include "swoole.h"
#include "client.h"
#include "server.h"
#include "coroutine.h"

#include <gtest/gtest.h>
#include <initializer_list>
#include <utility>

class coro_test
{
public:
    coro_test(coroutine_func_t _fn, void *_arg, int *_complete_num) :
            fn(_fn), arg(_arg), complete_num(_complete_num) { }

    void run()
    {
        fn(arg);
        (*complete_num)++;
    }

private:
    coroutine_func_t fn;
    void *arg;
    int *complete_num;
};

static void coro_test_fn(void *arg)
{
    ((coro_test*) arg)->run();
    delete (coro_test*) arg;
}

static inline void coro_test_create(coroutine_func_t fn, void *arg, int *complete_num)
{
    auto test = new coro_test(fn, arg, complete_num);
    long cid = swoole::Coroutine::create(coro_test_fn, test);
    ASSERT_GT(cid, 0);
}

static inline void coro_test(std::initializer_list<std::pair<coroutine_func_t, void*>> args)
{
    int complete_num = 0;
    swoole_event_init();
    SwooleTG.reactor->wait_exit = 1;
    for (const auto &arg : args)
    {
        coro_test_create(arg.first, arg.second, &complete_num);
    }
    swoole_event_wait();
}

static inline void coro_test(std::initializer_list<coroutine_func_t> args)
{
    int complete_num = 0;
    swoole_event_init();
    SwooleTG.reactor->wait_exit = 1;
    for (const auto &arg : args)
    {
        coro_test_create(arg, nullptr, &complete_num);
    }
    swoole_event_wait();
}

static inline void coro_test(coroutine_func_t fn, void *arg = nullptr)
{
    int complete_num = 0;
    swoole_event_init();
    SwooleTG.reactor->wait_exit = 1;
    coro_test_create(fn, arg, &complete_num);
    swoole_event_wait();
}

void create_test_server(swServer *serv);