#include "tests.h"

TEST(client, tcp)
{
    int ret;
    swClient cli;
    char buf[128];

    ret = swClient_create(&cli, SW_SOCK_TCP, SW_SOCK_SYNC);
    ASSERT_EQ(ret, 0);
    ret = cli.connect(&cli, (char *) "127.0.0.1", 9501, -1, 0);
    ASSERT_EQ(ret, 0);
    ret = cli.send(&cli, (char *) SW_STRS("echo"), 0);
    ASSERT_GT(ret, 0);
    ret = cli.recv(&cli, buf, 128, 0);
    ASSERT_GT(ret, 0);
    cli.close(&cli);
    ASSERT_EQ(strncmp(buf, SW_STRL("hello world\n")), 0);
}
