#include "tests.h"

// TEST(Server, Create)
// {
//     EXPECT_EQ(0, swoole_test::server_test());
// }

int main(int argc, char **argv)
{
    swoole_init();
    SwooleG.main_reactor = (swReactor *) sw_malloc(sizeof(swReactor));
    swReactor_create(SwooleG.main_reactor, SW_REACTOR_MAXEVENTS);
    swTimer_init(1);

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
