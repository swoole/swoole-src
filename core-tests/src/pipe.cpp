#include "tests.h"

TEST(pipe, unixsock)
{
    swPipe p;
    char buf[1024];
    bzero(&p, sizeof(p));
    int ret = swPipeUnsock_create(&p, 1, SOCK_DGRAM);
    ASSERT_EQ(ret, 0);

    ret = p.write(&p, (void*) SW_STRL("hello world1"));
    ASSERT_GT(ret, 0);
    ret = p.write(&p, (void*) SW_STRL("hello world2"));
    ASSERT_GT(ret, 0);
    ret = p.write(&p, (void*) SW_STRL("hello world3"));
    ASSERT_GT(ret, 0);

    //1
    ret = p.read(&p, buf, 65535);
    ASSERT_GT(ret, 0);
    ASSERT_EQ(strcmp("hello world1", buf), 0);
    //2
    ret = p.read(&p, buf, 65535);
    ASSERT_GT(ret, 0);
    ASSERT_EQ(strcmp("hello world2", buf), 0);
    //3
    ret = p.read(&p, buf, 65535);
    ASSERT_GT(ret, 0);
    ASSERT_EQ(strcmp("hello world3", buf), 0);
}

TEST(pipe, base)
{
    swPipe p;
    int ret;
    char data[256];

    ret = swPipeBase_create(&p, 1);
    ASSERT_EQ(ret, 0);
    ret = p.write(&p, (void *) SW_STRL("hello world\n") - 1);
    ASSERT_GT(ret, 0);
    ret = p.write(&p, (void *) SW_STRL("你好中国。\n") - 1);
    ASSERT_GT(ret, 0);

    bzero(data, 256);
    ret = p.read(&p, data, 255);
    ASSERT_GT(ret, 0);
    ASSERT_EQ(strcmp("hello world\n你好中国。\n", data), 0);
}
