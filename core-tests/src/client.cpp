#include "tests.h"

TEST(client, tcp)
{
    int ret;
    swClient cli, cli2;
    char buf[128];

    ret = swClient_create(&cli, SW_SOCK_TCP, SW_SOCK_SYNC);
    ASSERT_EQ(ret, 0);
    ret = cli.connect(&cli, (char *) "127.0.0.1", 80, 0.5, 0);
    ASSERT_EQ(ret, 0);
    ret = cli.send(&cli, (char *) SW_STRL("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"), 0);
    ASSERT_GT(ret, 0);
    ret = cli.recv(&cli, buf, 128, 0);
    ASSERT_GT(ret, 0);
    cli.close(&cli);
    ASSERT_EQ(strncmp(buf, SW_STRL("HTTP/1.1 200 OK\r\n") -1), 0);
}
