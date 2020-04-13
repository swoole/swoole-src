#pragma once

#include "tests.h"

using namespace swoole;

typedef void (*_onStart)(swServer *serv);
typedef void (*_onShutdown)(swServer *serv);
typedef void (*_onPipeMessage)(swServer *, swEventData *data);
typedef void (*_onWorkerStart)(swServer *serv, int worker_id);
typedef void (*_onWorkerStop)(swServer *serv, int worker_id);
typedef int (*_onReceive)(swServer *, swEventData *);
typedef int (*_onPacket)(swServer *, swEventData *);
typedef void (*_onClose)(swServer *serv, swDataHead *);
typedef void (*_onConnect)(swServer *serv, swDataHead *);

namespace swoole { namespace test {
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
    server(std::string _host, int _port, int _mode, int _type);
    ~server();
    void on(std::string event, void *fn);
    bool start();
    bool listen(std::string host, int port,  enum swSocket_type type);
    size_t get_packet(swServer *serv, swEventData *req, char **data_ptr);
    ssize_t sendto(swSocketAddress *address, const char *__buf, size_t __n, int server_socket = -1);
};
}
}
