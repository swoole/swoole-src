/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | @link     https://www.swoole.com/                                    |
  | @contact  team@swoole.com                                            |
  | @license  https://github.com/swoole/swoole-src/blob/master/LICENSE   |
  | @author   Tianfeng Han  <mikan.tenny@gmail.com>                      |
  +----------------------------------------------------------------------+
*/

#include "tests.h"
#include "test_server.h"

using namespace swoole::test;

Server::Server(std::string _host, int _port, int _mode, int _type):
        host(_host), port(_port), mode(_mode), type(_type)
{
    serv.worker_num = 1;

    if (mode == SW_MODE_BASE)
    {
        serv.reactor_num = 1;
        serv.worker_num = 1;
    }

    serv.factory_mode = (uint8_t) mode;
    serv.dispatch_mode = 2;
    serv.ptr2 = this;

    //create Server
    int ret = swServer_create(&serv);
    if (ret < 0)
    {
        swTrace("create server fail[error=%d].\n", ret);
        exit(0);
    }
    this->listen(host, port, (swSocket_type) type);
}

Server::~Server()
{
}

void Server::on(std::string event, void *fn)
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

bool Server::start()
{
    int ret = swServer_start(&serv);
    if (ret < 0)
    {
        swTrace("start server fail[error=%d].\n", ret);
        return false;
    }
    return true;
}

bool Server::listen(std::string host, int port, enum swSocket_type type)
{
    swListenPort *ls = swServer_add_port(&serv, type, (char *) host.c_str(), port);
    if (ls == nullptr)
    {
        return false;
    }

    ports.push_back(ls);
    return true;
}

size_t Server::get_packet(swEventData *req, char **data_ptr)
{
    return serv.get_packet(&serv, req, data_ptr);
}

int Server::send(int session_id, void *data, uint32_t length)
{
    return serv.send(&serv, session_id, data, length);
}

ssize_t Server::sendto(swSocketAddress *address, const char *__buf, size_t __n, int server_socket)
{
    char ip[256];
    uint16_t port;

    inet_ntop(AF_INET, (void *) &address->addr.inet_v4.sin_addr, ip, sizeof(ip));
    port = ntohs(address->addr.inet_v4.sin_port);

    return swSocket_udp_sendto(server_socket, ip, port, __buf, __n);
}

int Server::close(int session_id, int reset)
{
    return serv.close(&serv, session_id, reset);
}
