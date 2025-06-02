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
#define TEST_HOST6 "::1"
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
#define TEST_SOCKS5_PROXY_NO_AUTH_PORT 8081
#define TEST_SOCKS5_PROXY_USER "user"
#define TEST_SOCKS5_PROXY_PASSWORD "password"

#define TEST_DOMAIN_BAIDU "www.baidu.com"

#define TEST_HTTP_DOMAIN "www.gov.cn"
#define TEST_HTTP_EXPECT "Location: https://www.gov.cn/"
#define TEST_HTTPS_EXPECT "中国政府网"

#define TEST_STR "hello world, hello swoole\n"
#define TEST_STR2 "I am Rango\n"

#define TEST_LOG_FILE "/tmp/swoole.log"
#define TEST_SOCK_FILE "/tmp/swoole-core-tests.sock"

#define TEST_COUNTER_NUM 32

#define TEST_REQUEST_BAIDU                                                                                             \
    "GET / HTTP/1.1\r\n"                                                                                               \
    "Host: www.baidu.com\r\n"                                                                                          \
    "Connection: close\r\n"                                                                                            \
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) "                         \
    "Chrome/51.0.2704.106 Safari/537.36"                                                                               \
    "\r\n\r\n"

#define ASSERT_MEMEQ(x, y, n) ASSERT_EQ(memcmp((x), (y), n), 0)
#define EXPECT_MEMEQ(x, y, n) EXPECT_EQ(memcmp((x), (y), n), 0)
#define ASSERT_ERREQ(x) ASSERT_EQ(swoole_get_last_error(), x)
#define EXPECT_ERREQ(x) EXPECT_EQ(swoole_get_last_error(), x)

#define TIMER_PARAMS swoole::Timer *timer, swoole::TimerNode *tnode

#ifdef SW_VERBOSE
#define DEBUG() swoole::test::debug_output.get()
#define debug_info printf
#else
#define DEBUG() swoole::test::null_stream
#define debug_info(...)
#endif

namespace swoole {
struct HttpProxy;
struct Socks5Proxy;
namespace test {
class NullStream : public std::ostream {
  public:
    NullStream() : std::ostream(nullptr) {}
};

extern NullStream null_stream;
extern std::reference_wrapper<std::ostream> debug_output;
const std::string &get_root_path();
std::string get_ssl_dir();
std::string get_jpg_file();
bool is_github_ci();
int exec_js_script(const std::string &file, const std::string &args);
std::string http_get_request(const std::string &domain, const std::string &path);
int get_random_port();
int has_threads();
int has_child_processes();
int wait_all_child_processes(bool verbose = false);

pid_t spawn_exec(const std::function<void(void)> &fn);
int spawn_exec_and_wait(const std::function<void(void)> &fn);

void counter_init();
int *counter_ptr();
int counter_incr(int index, int add = 1);
int counter_get(int index);
void counter_set(int index, int value);
void counter_incr_and_put_log(int index, const char *msg);

int dump_cert_info(const char *data, size_t len);
int recursive_rmdir(const char *path);

static inline int dump_cert_info(const String *str) {
    return dump_cert_info(str->str, str->length);
}

}  // namespace test
};  // namespace swoole
