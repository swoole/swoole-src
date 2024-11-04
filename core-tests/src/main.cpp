#include "test_core.h"

#include "swoole_proxy.h"

using namespace swoole;
using namespace std;

static string root_path;

static void init_root_path(const char *);

int main(int argc, char **argv) {
    swoole_init();
    init_root_path(argv[0]);

    if (getenv("DISPLAY_BACKTRACE") != nullptr) {
        sw_logger()->display_backtrace();
    }

    ::testing::InitGoogleTest(&argc, argv);
    int retval = RUN_ALL_TESTS();

    swoole_clean();

    return retval;
}

static void init_root_path(const char *_exec_file) {
    char buf[PATH_MAX];
    string file;
    if (_exec_file[0] == '/') {
        file = _exec_file;
    } else {
        char *dir = getcwd(buf, sizeof(buf));
        file = string(dir) + "/" + _exec_file;
    }
    string relative_root_path = file.substr(0, file.rfind('/')) + "/../../";
    char *_realpath = realpath(relative_root_path.c_str(), buf);
    if (_realpath == nullptr) {
        root_path = relative_root_path;
    } else {
        root_path = string(_realpath);
    }
}

namespace swoole {
namespace test {

const string &get_root_path() {
    return root_path;
}

string get_jpg_file() {
    return root_path + TEST_JPG_FILE;
}

bool is_github_ci() {
    return getenv("GITHUB_ACTIONS") != nullptr;
}

Socks5Proxy *create_socks5_proxy() {
    auto socks5_proxy = new Socks5Proxy();
    socks5_proxy->host = std::string(TEST_SOCKS5_PROXY_HOST);
    socks5_proxy->port = TEST_SOCKS5_PROXY_PORT;
    socks5_proxy->dns_tunnel = 1;

    printf("GITHUB_ACTIONS=%s, GITHUB_ACTION=%s\n", getenv("GITHUB_ACTIONS"), getenv("GITHUB_ACTION"));

    if (is_github_ci()) {
        socks5_proxy->method = SW_SOCKS5_METHOD_AUTH;
        socks5_proxy->username = std::string(TEST_SOCKS5_PROXY_USER);
        socks5_proxy->password = std::string(TEST_SOCKS5_PROXY_PASSWORD);
    }
    return socks5_proxy;
}

HttpProxy *create_http_proxy() {
    auto http_proxy = new HttpProxy();
    http_proxy->proxy_host = std::string(TEST_HTTP_PROXY_HOST);
    http_proxy->proxy_port = TEST_HTTP_PROXY_PORT;
    if (is_github_ci()) {
        http_proxy->username = std::string(TEST_HTTP_PROXY_USER);
        http_proxy->password = std::string(TEST_HTTP_PROXY_PASSWORD);
    }
    return http_proxy;
}

}  // namespace test
}  // namespace swoole
