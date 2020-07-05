#include "tests.h"

using namespace swoole;

int main(int argc, char **argv)
{
    swoole_init();

    ::testing::InitGoogleTest(&argc, argv);
    int retval = RUN_ALL_TESTS();

    swoole_clean();

    return retval;
}
