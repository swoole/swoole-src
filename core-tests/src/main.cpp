#include "tests.h"
#include "swoole/swoole_api.h"

using namespace swoole;

int main(int argc, char **argv)
{
    swoole_init();

    ::testing::InitGoogleTest(&argc, argv);
    int retval = RUN_ALL_TESTS();

    return retval;
}
