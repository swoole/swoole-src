#pragma once

#include "test_core.h"

#define SERVER_THIS ((swoole::test::Server *) serv->ptr2)

#define ON_WORKERSTART_PARAMS   swServer *serv, int worker_id
#define ON_PACKET_PARAMS        swServer *serv, swRecvData *req
#define ON_RECEIVE_PARAMS       swServer *serv, swRecvData *req

typedef void (*_onStart)(swServer *serv);
typedef void (*_onShutdown)(swServer *serv);
typedef void (*_onPipeMessage)(swServer *, swEventData *data);
typedef void (*_onWorkerStart)(swServer *serv, int worker_id);
typedef void (*_onWorkerStop)(swServer *serv, int worker_id);
typedef int (*_onReceive)(swServer *, swRecvData *);
typedef int (*_onPacket)(swServer *, swRecvData *);
typedef void (*_onClose)(swServer *serv, swDataHead *);
typedef void (*_onConnect)(swServer *serv, swDataHead *);

using on_workerstart_lambda_type = void (*)(ON_WORKERSTART_PARAMS);
using on_receive_lambda_type = void (*)(ON_RECEIVE_PARAMS);
using on_packet_lambda_type = void (*)(ON_PACKET_PARAMS);

namespace swoole { namespace test {
//--------------------------------------------------------------------------------------------------------
class Server
{
private:
    swoole::Server serv;
    std::vector<swListenPort *> ports;
    std::unordered_map<std::string, void *> private_data;
    std::string host;
    int port;
    int mode;
    int type;

public:
    swDgramPacket *packet = nullptr;

    Server(std::string _host, int _port, swoole::Server::Mode _mode, int _type);
    ~Server();
    void on(std::string event, void *fn);
    bool start();
    bool listen(std::string host, int port, enum swSocket_type type);
    int send(int session_id, const void *data, uint32_t length);
    ssize_t sendto(const swSocketAddress &address, const char *__buf, size_t __n, int server_socket = -1);
    int close(int session_id, int reset);

    inline void* get_private_data(const std::string &key)
    {
        auto it = private_data.find(key);
        if (it == private_data.end())
        {
            return nullptr;
        }
        else
        {
            return it->second;
        }
    }

    inline void set_private_data(const std::string &key, void *data)
    {
        private_data[key] = data;
    }
};
//--------------------------------------------------------------------------------------------------------
}}
