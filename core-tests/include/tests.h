#pragma once

#include "swoole.h"
#include "client.h"
#include "server.h"
#include "coroutine.h"
#include "socket.h"

#include <gtest/gtest.h>
#include <initializer_list>
#include <pair>

static inline void coro_test_wait()
{
    SwooleG.main_reactor->wait(SwooleG.main_reactor, nullptr);
}

static inline void coro_test_create(coroutine_func_t fn, void *arg = nullptr)
{
    long cid = swoole::Coroutine::create(fn, arg);
    ASSERT_GT(cid, 0);
}

static inline void coro_test(std::initializer_list<std::pair<coroutine_func_t, void*>> args)
{
    for (const auto &arg : args)
    {
        coro_test_create(args.first, arg.second);
    }

    coro_test_wait();
}

static inline void coro_test(coroutine_func_t fn, void *arg)
{
    coro_test_create(fn, arg);
    coro_test_wait();
}