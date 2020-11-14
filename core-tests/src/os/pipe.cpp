#include "test_core.h"
#include "swoole_pipe.h"

using namespace swoole;

TEST(pipe, unixsock) {
    UnixSocket p(true, SOCK_DGRAM);
    ASSERT_TRUE(p.ready());

    char buf[1024];

    int ret = p.write((void *) SW_STRS("hello world1"));
    ASSERT_GT(ret, 0);
    ret = p.write((void *) SW_STRS("hello world2"));
    ASSERT_GT(ret, 0);
    ret = p.write((void *) SW_STRS("hello world3"));
    ASSERT_GT(ret, 0);

    // 1
    ret = p.read(buf, sizeof(buf));
    if (ret < 0) {
        swSysWarn("read() failed.");
    }
    ASSERT_GT(ret, 0);
    ASSERT_EQ(strcmp("hello world1", buf), 0);
    // 2
    ret = p.read(buf, sizeof(buf));
    ASSERT_GT(ret, 0);
    ASSERT_EQ(strcmp("hello world2", buf), 0);
    // 3
    ret = p.read(buf, sizeof(buf));
    ASSERT_GT(ret, 0);
    ASSERT_EQ(strcmp("hello world3", buf), 0);
}

TEST(pipe, base) {
    int ret;
    char data[256];

    Pipe p(true);
    ASSERT_TRUE(p.ready());


    ret = p.write((void *) SW_STRL("hello world\n"));
    ASSERT_GT(ret, 0);
    ret = p.write((void *) SW_STRL("你好中国。\n"));
    ASSERT_GT(ret, 0);

    sw_memset_zero(data, 256);
    ret = p.read(data, 255);
    ASSERT_GT(ret, 0);
    ASSERT_EQ(strcmp("hello world\n你好中国。\n", data), 0);
}
