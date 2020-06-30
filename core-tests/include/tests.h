#pragma once

#ifdef HAVE_SWOOLE_DIR
#include "swoole.h"
#include "client.h"
#include "server.h"
#include "swoole_cxx.h"
#else
#include "swoole/swoole.h"
#include "swoole/client.h"
#include "swoole/server.h"
#include "swoole/swoole_cxx.h"
#endif

#include <gtest/gtest.h>

#include <functional>
#include <utility>
#include <initializer_list>
#include <string>
#include <vector>
#include <set>
#include <thread>
#include <mutex>
#include <unordered_map>

#define TEST_HOST "127.0.0.1"
#define TEST_PORT 9501
