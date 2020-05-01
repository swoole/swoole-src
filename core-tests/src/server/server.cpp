#include "test_server.h"

using namespace std;

TEST(server, create_pipe_buffers)
{
    int ret;
    swServer serv;

    create_test_server(&serv);

    ret = swServer_create_pipe_buffers(&serv);
    ASSERT_EQ(0, ret);
    ASSERT_NE(nullptr, serv.pipe_buffers);
    for (uint32_t i = 0; i < serv.reactor_num; i++)
    {
        ASSERT_NE(nullptr, serv.pipe_buffers[i]);
    }
}