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

#ifdef SW_VERBOSE
    swoole_set_log_level(SW_LOG_TRACE);
    swoole_set_trace_flags(SW_TRACE_ALL);
#endif

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
NullStream null_stream;

const string &get_root_path() {
    return root_path;
}

string get_ssl_dir() {
    return get_root_path() + "/tests/include/ssl_certs";
}

string get_jpg_file() {
    return root_path + TEST_JPG_FILE;
}

string http_get_request(const string &domain, const string &path) {
    return "GET " + path +
           " HTTP/1.1\r\n"
           "Host: " +
           domain +
           "\r\n"
           "Connection: close\r\n"
           "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/51.0.2704.106 Safari/537.36"
           "\r\n\r\n";
}

bool is_github_ci() {
    return getenv("GITHUB_ACTIONS") != nullptr;
}

int exec_js_script(const std::string &file, const std::string &args) {
    std::string command = "bash -c 'node " + test::get_root_path() + "/core-tests/js/" + file + " " + args + "'";
    return std::system(command.c_str());
}

int get_random_port() {
    return TEST_PORT + swoole_system_random(1, 10000);
}

pid_t spawn_exec(const std::function<void(void)> &fn) {
    pid_t child_pid = fork();
    if (child_pid == -1) {
        throw std::system_error();
    } else if (child_pid == 0) {
        fn();
        exit(0);
    }
    return child_pid;
}

int spawn_exec_and_wait(const std::function<void(void)> &fn) {
    int status;
    pid_t pid = spawn_exec(fn);
    if (swoole_waitpid(pid, &status, 0) == pid) {
        return status;
    } else {
        return -1;
    }
}

}  // namespace test
}  // namespace swoole
