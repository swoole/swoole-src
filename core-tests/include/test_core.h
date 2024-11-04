#pragma once

#include "swoole_api.h"
#include "swoole_client.h"

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
#include <fstream>

#define TEST_HOST "127.0.0.1"
#define TEST_PORT 9501
#define TEST_TMP_FILE "/tmp/swoole_core_test_file"
#define TEST_TMP_DIR "/tmp/swoole_core_test_dir"
#define TEST_JPG_FILE "/examples/test.jpg"
#define TEST_JPG_MD5SUM "64a42b4c0f3c65a14c23b60d3880a917"

#define TEST_HTTP_PROXY_HOST "127.0.0.1"
#define TEST_HTTP_PROXY_PORT 8888
#define TEST_HTTP_PROXY_USER "user"
#define TEST_HTTP_PROXY_PASSWORD "password"

#define TEST_SOCKS5_PROXY_HOST "127.0.0.1"
#define TEST_SOCKS5_PROXY_PORT 8080
#define TEST_SOCKS5_PROXY_USER "user"
#define TEST_SOCKS5_PROXY_PASSWORD "password"

#define TEST_DOMAIN_BAIDU "www.baidu.com"

#define TEST_REQUEST_BAIDU                                                                                             \
    "GET / HTTP/1.1\r\n"                                                                                               \
    "Host: www.baidu.com\r\n"                                                                                          \
    "Connection: close\r\n"                                                                                            \
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) "                         \
    "Chrome/51.0.2704.106 Safari/537.36"                                                                               \
    "\r\n\r\n"

#define ASSERT_MEMEQ(x, y, n) ASSERT_EQ(memcmp((x), (y), n), 0)
#define EXPECT_MEMEQ(x, y, n) EXPECT_EQ(memcmp((x), (y), n), 0)

namespace swoole {
struct HttpProxy;
struct Socks5Proxy;
namespace test {

const std::string &get_root_path();
std::string get_jpg_file();
bool is_github_ci();

int get_random_port();

Socks5Proxy *create_socks5_proxy();
HttpProxy *create_http_proxy();

}  // namespace test
};  // namespace swoole
