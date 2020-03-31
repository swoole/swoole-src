#include "tests.h"

#define GREETER "Hello Swoole"
#define GREETER_SIZE sizeof(GREETER)

TEST(client, tcp)
{
    int ret;
    swClient cli;
    char buf[128];

    ret = swClient_create(&cli, SW_SOCK_TCP, SW_SOCK_SYNC);
    ASSERT_EQ(ret, 0);
    ret = cli.connect(&cli, "127.0.0.1", 9501, -1, 0);
    ASSERT_EQ(ret, 0);
    ret = cli.send(&cli, SW_STRS(GREETER), 0);
    ASSERT_GT(ret, 0);
    ret = cli.recv(&cli, buf, 128, 0);
    ASSERT_EQ(ret, GREETER_SIZE);
    ASSERT_STREQ(GREETER, buf);
    cli.close(&cli);
}
