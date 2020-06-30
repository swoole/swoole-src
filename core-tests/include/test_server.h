#pragma once

#include "tests.h"

void create_test_server(swServer *serv);

#define SERVER_THIS ((server *) serv->ptr2)

#define ON_WORKERSTART_PARAMS   swServer *serv, int worker_id
#define ON_PACKET_PARAMS        swServer *serv, swEventData *req
#define ON_RECEIVE_PARAMS       swServer *serv, swEventData *req

typedef void (*_onStart)(swServer *serv);
typedef void (*_onShutdown)(swServer *serv);
typedef void (*_onPipeMessage)(swServer *, swEventData *data);
typedef void (*_onWorkerStart)(swServer *serv, int worker_id);
typedef void (*_onWorkerStop)(swServer *serv, int worker_id);
typedef int (*_onReceive)(swServer *, swEventData *);
typedef int (*_onPacket)(swServer *, swEventData *);
typedef void (*_onClose)(swServer *serv, swDataHead *);
typedef void (*_onConnect)(swServer *serv, swDataHead *);

using on_workerstart_lambda_type = void (*)(ON_WORKERSTART_PARAMS);
using on_receive_lambda_type = void (*)(ON_RECEIVE_PARAMS);
using on_packet_lambda_type = void (*)(ON_PACKET_PARAMS);

namespace swoole
{
namespace test
{
class server
{
private:
    swServer serv;
    std::vector<swListenPort *> ports;
    std::string host;
    int port;
    int mode;
    int type;

public:
    swDgramPacket *packet = nullptr;

    server(std::string _host, int _port, int _mode, int _type);
    ~server();
    void on(std::string event, void *fn);
    bool start();
    bool listen(std::string host, int port, enum swSocket_type type);
    size_t get_packet(swEventData *req, char **data_ptr);
    int send(int session_id, void *data, uint32_t length);
    ssize_t sendto(swSocketAddress *address, const char *__buf, size_t __n, int server_socket = -1);
    int close(int session_id, int reset);
};
}
}
