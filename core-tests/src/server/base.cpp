#include "tests.h"
#include "wrapper/server.h"

using swoole::test::server;

server::server(std::string _host, int _port, int _mode, int _type):
        host(_host), port(_port), mode(_mode), type(_type)
{
    swServer_init(&serv);

    serv.worker_num = 1;

    if (mode == SW_MODE_BASE)
    {
        serv.reactor_num = 1;
        serv.worker_num = 1;
    }

    serv.factory_mode = (uint8_t) mode;
    serv.dispatch_mode = 2;

    //create Server
    int ret = swServer_create(&serv);
    if (ret < 0)
    {
        swTrace("create server fail[error=%d].\n", ret);
        exit(0);
    }
    this->listen(host, port, (swSocket_type) type);
}

server::~server()
{
}

void server::on(std::string event, void *fn)
{
    if (event == "Start")
    {
        serv.onStart = (_onStart) fn;
    }
    else if (event == "onShutdown")
    {
        serv.onShutdown = (_onShutdown) fn;
    }
    else if (event == "onPipeMessage")
    {
        serv.onPipeMessage = (_onPipeMessage) fn;
    }
    else if (event == "onWorkerStart")
    {
        serv.onWorkerStart = (_onWorkerStart) fn;
    }
    else if (event == "onWorkerStop")
    {
        serv.onWorkerStop = (_onWorkerStop) fn;
    }
    else if (event == "onReceive")
    {
        serv.onReceive = (_onReceive) fn;
    }
    else if (event == "onPacket")
    {
        serv.onPacket = (_onPacket) fn;
    }
    else if (event == "onClose")
    {
        serv.onClose = (_onClose) fn;
    }
    else
    {
        serv.onConnect = (_onConnect) fn;
    }
}

bool server::start()
{
    serv.ptr2 = this;

    int ret = swServer_start(&serv);
    if (ret < 0)
    {
        swTrace("start server fail[error=%d].\n", ret);
        return false;
    }
    return true;
}

bool server::listen(std::string host, int port, enum swSocket_type type)
{
    swListenPort *ls = swServer_add_port(&serv, type, (char *) host.c_str(), port);
    if (ls == nullptr)
    {
        return false;
    }

    ports.push_back(ls);
    return true;
}

size_t server::get_packet(swEventData *req, char **data_ptr)
{
    return serv.get_packet(&serv, req, data_ptr);
}

int server::send(int session_id, void *data, uint32_t length)
{
    return serv.send(&serv, session_id, data, length);
}

ssize_t server::sendto(swSocketAddress *address, const char *__buf, size_t __n, int server_socket)
{
    char ip[256];
    uint16_t port;

    inet_ntop(AF_INET, (void *) &address->addr.inet_v4.sin_addr, ip, sizeof(ip));
    port = ntohs(address->addr.inet_v4.sin_port);

    return swSocket_udp_sendto(server_socket, ip, port, __buf, __n);
}

int server::close(int session_id, int reset)
{
    return serv.close(&serv, session_id, reset);
}

void create_test_server(swServer *serv)
{
    swServer_init(serv);

    swServer_create(serv);

    SwooleG.memory_pool = swMemoryGlobal_new(SW_GLOBAL_MEMORY_PAGESIZE, 1);
    serv->workers = (swWorker *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, serv->worker_num * sizeof(swWorker));
    swFactoryProcess_create(&serv->factory, serv->worker_num);
}