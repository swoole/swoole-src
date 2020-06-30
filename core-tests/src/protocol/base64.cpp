#include "tests.h"
#include "base64.h"

TEST(base64, encode)
{
    char inbuf[1024];
    char outbuf[2048];

    auto n = swoole_random_bytes(inbuf, sizeof(inbuf) - 1);
    auto n2 = swBase64_encode((uchar*) inbuf, n, outbuf);
    ASSERT_GT(n2, n);
}

TEST(base64, decode)
{
    const char *inbuf = "aGVsbG8gd29ybGQ=";
    char outbuf[2048];

    auto n2 = swBase64_decode(inbuf, strlen(inbuf), outbuf);
    ASSERT_EQ(std::string(outbuf, n2), "hello world");
}
