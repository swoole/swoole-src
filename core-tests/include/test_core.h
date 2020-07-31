#pragma once

#include "swoole_api.h"
#include "client.h"
#include "server.h"

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
#define TEST_TMP_FILE "/tmp/swoole_core_test_file"
#define TEST_JPG_FILE "/examples/test.jpg"
#define TEST_JPG_MD5SUM  "64a42b4c0f3c65a14c23b60d3880a917"

namespace swoole { namespace test {
const std::string &get_root_path();
std::string get_jpg_file();
}};
