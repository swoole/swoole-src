#include "tests.h"
#include "swoole_cxx.h"

using namespace std;

TEST(server_process, create_pipes)
{
    int ret;
    swServer serv;
    
    create_test_server(&serv);

    ret = swFactoryProcess_create_pipes(&serv.factory);
    ASSERT_EQ(0, ret);
    for (uint32_t i = 0; i < serv.worker_num; i++)
    {
        ASSERT_NE(nullptr, serv.workers[i].pipe_master);
        ASSERT_NE(nullptr, serv.workers[i].pipe_worker);
    }
}