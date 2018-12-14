#pragma once

#include "swoole.h"
#include "client.h"
#include "server.h"
#include "coroutine.h"
#include "socket.h"
#include <gtest/gtest.h>

#define CORO_TEST_START(NAME) \
    bool (NAME) = false; \
    if (Coroutine::create([](void *arg) \
    {

#define CORO_TEST_END(NAME) \
        *(bool *)arg = true; \
    }, &(NAME)) < 0) \
    { \
        return; \
    }

#define CORO_TEST_WAIT(NAME) \
    SwooleG.main_reactor->once = 1; \
    while (!(NAME)) \
    { \
        SwooleG.main_reactor->wait(SwooleG.main_reactor, nullptr); \
        SwooleG.main_reactor->running = 1; \
    } \
    SwooleG.main_reactor->once = 0;
