#pragma once

#include "wrapper/server.hpp"

using namespace std;
using namespace swoole;

class TestServer : public Server
{
public:
    TestServer(string _host, int _port, int _mode = SW_MODE_PROCESS, enum swSocket_type _type = SW_SOCK_TCP) :
            Server(_host, _port, _mode, _type)
    {
        serv.worker_num = 1;
    }

    virtual void onStart();
    virtual void onShutdown() {};
    virtual void onWorkerStart(int worker_id);
    virtual void onWorkerStop(int worker_id) {}
    virtual void onPipeMessage(int src_worker_id, const DataBuffer &) {}
    virtual void onReceive(int fd, const DataBuffer &data);
    virtual void onConnect(int fd);
    virtual void onClose(int fd);
    virtual void onPacket(const DataBuffer &data, ClientInfo &clientInfo);

    virtual void onTask(int task_id, int src_worker_id, const DataBuffer &data);
    virtual void onFinish(int task_id, const DataBuffer &data);
};

