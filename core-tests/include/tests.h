#pragma once

#ifdef HAVE_SWOOLE_DIR
#include "swoole_api.h"
#include "swoole_cxx.h"
#include "client.h"
#include "server.h"
#else
#include "swoole/swoole_api.h"
#include "swoole/swoole_cxx.h"
#include "swoole/client.h"
#include "swoole/server.h"
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

`namespace swoole { namespace test {
const std::string &get_root_path();
}};
