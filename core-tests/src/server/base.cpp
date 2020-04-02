#include "wrapper/server.h"
#include "swoole/wrapper/server.hpp"
#include "swoole/swoole_api.h"
#include "swoole/server.h"

using namespace swoole;

void TestServer::onReceive(int fd, const DataBuffer &data)
{
    if (data.length >= sizeof("close") && memcmp(data.buffer, SW_STRS("close")) == 0)
    {
        this->close(fd);
    }
    else
    {
        this->send(fd, (char *) data.buffer, data.length);
    }
}

void TestServer::onPacket(const DataBuffer &data, ClientInfo &clientInfo)
{
}

void TestServer::onConnect(int fd)
{
}

void TestServer::onClose(int fd)
{
}

void TestServer::onTask(int task_id, int src_worker_id, const DataBuffer &data)
{
}

void TestServer::onFinish(int task_id, const DataBuffer &data)
{
}

void TestServer::onStart()
{
}

void TestServer::onWorkerStart(int worker_id)
{
}

void create_test_server(swServer *serv)
{
    swServer_init(serv);

    swServer_create(serv);

    SwooleG.memory_pool = swMemoryGlobal_new(SW_GLOBAL_MEMORY_PAGESIZE, 1);
    serv->workers = (swWorker *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, serv->worker_num * sizeof(swWorker));
    swFactoryProcess_create(&serv->factory, serv->worker_num);
}