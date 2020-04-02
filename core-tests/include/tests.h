#pragma once

#include "wrapper/coroutine.h"

#include "swoole/swoole.h"
#include "swoole/client.h"
#include "swoole/server.h"

#include <gtest/gtest.h>
#include <initializer_list>
#include <utility>

void create_test_server(swServer *serv);