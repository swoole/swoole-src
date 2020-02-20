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