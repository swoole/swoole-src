#include "test_core.h"

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

}  // namespace test
}  // namespace swoole
