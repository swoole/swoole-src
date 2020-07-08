#include "tests.h"

using namespace swoole;
using namespace std;

static string root_path;

static void init_root_path(const char *);

int main(int argc, char **argv)
{
    swoole_init();
    init_root_path(argv[0]);

    ::testing::InitGoogleTest(&argc, argv);
    int retval = RUN_ALL_TESTS();

    swoole_clean();

    return retval;
}

static void init_root_path(const char *_exec_file) {
    char buf[PATH_MAX];
    char *dir = getcwd(buf, sizeof(buf));
    string file = string(dir) + "/" + _exec_file;
    string relative_root_path = file.substr(0, file.rfind('/')) + "/../../";
    char *_realpath = realpath(relative_root_path.c_str(), buf);
    if (_realpath == nullptr)
    {
        root_path = relative_root_path;
    }
    else
    {
        root_path = string(_realpath);
    }
}

const string &swoole::test::get_root_path() {
    return root_path;
}
