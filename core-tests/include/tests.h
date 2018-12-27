#pragma once

#include "swoole.h"
#include "client.h"
#include "server.h"
#include "coroutine.h"
#include "socket.h"
#include <gtest/gtest.h>

inline void coro_test_wait()
{
    SwooleG.main_reactor->wait(SwooleG.main_reactor, nullptr);
}

inline void coro_test_create(coroutine_func_t fn, void *arg = nullptr)
{
    long cid = swoole::Coroutine::create(fn, arg);
    ASSERT_GT(cid, 0);
}

inline void coro_test(coroutine_func_t fn, void *arg = nullptr)
{
    coro_test_create(fn, arg);
    coro_test_wait();
}

inline void coro_test(coroutine_func_t *fns, size_t num, void **args = nullptr)
{
    size_t i;
    for (i = 0; i < num; ++i)
    {
        coro_test_create(fns[i], args ? args[i] : nullptr);
    }

    coro_test_wait();
}