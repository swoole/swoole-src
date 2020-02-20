#include "tests.h"
#include "swoole_cxx.h"

using namespace std;

TEST(server, set_ipc_max_size)
{
    int ret;
    swServer serv;

    create_test_server(&serv);

    ret = swFactoryProcess_create_pipes(&serv.factory);
    ASSERT_EQ(0, ret);
    swServer_set_ipc_max_size(&serv);
    ASSERT_GT(serv.ipc_max_size, 0);
}

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