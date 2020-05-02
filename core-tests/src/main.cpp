#include "tests.h"
#ifdef HAVE_SWOOLE_DIR
#include "swoole_api.h"
#else
#include "swoole/swoole_api.h"
#endif

using namespace swoole;

int main(int argc, char **argv)
{
    swoole_init();

    ::testing::InitGoogleTest(&argc, argv);
    int retval = RUN_ALL_TESTS();

    return retval;
}
