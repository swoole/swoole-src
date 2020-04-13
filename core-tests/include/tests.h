#pragma once

#include "wrapper/coroutine.h"

#include "swoole/swoole.h"
#include "swoole/client.h"
#include "swoole/server.h"

#include <gtest/gtest.h>

#include <functional>
#include <utility>
#include <initializer_list>
#include <string>
#include <vector>
#include <set>
#include <unordered_map>

#define TEST_HOST "127.0.0.1"
#define TEST_PORT 9501

void create_test_server(swServer *serv);