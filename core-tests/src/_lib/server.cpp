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
  | @Author   Tianfeng Han  <rango@swoole.com>                           |
  +----------------------------------------------------------------------+
*/

#include "test_core.h"
#include "test_server.h"
#include "swoole_memory.h"

using namespace swoole::test;
using swoole::network::Address;

Server::Server(std::string _host, int _port, swoole::Server::Mode _mode, int _type)
    : serv(_mode), host(_host), port(_port), mode(_mode), type(_type) {
    serv.worker_num = 1;

    if (mode == swoole::Server::MODE_BASE) {
        serv.reactor_num = 1;
        serv.worker_num = 1;
    }

    serv.dispatch_mode = 2;
    serv.private_data_2 = this;

    if (!listen(host, port, (swSocketType) type)) {
        swoole_warning("listen(%s:%d) fail[error=%d].", host.c_str(), port, errno);
        exit(0);
    }

    if (serv.create() < 0) {
        swoole_warning("create server fail[error=%d].", errno);
        exit(0);
    }
}

Server::~Server() {}

void Server::on(std::string event, void *fn) {
    if (event == "Start") {
        serv.onStart = (_onStart) fn;
    } else if (event == "onShutdown") {
        serv.onShutdown = (_onShutdown) fn;
    } else if (event == "onPipeMessage") {
        serv.onPipeMessage = (_onPipeMessage) fn;
    } else if (event == "onWorkerStart") {
        serv.onWorkerStart = (_onWorkerStart) fn;
    } else if (event == "onWorkerStop") {
        serv.onWorkerStop = (_onWorkerStop) fn;
    } else if (event == "onReceive") {
        serv.onReceive = (_onReceive) fn;
    } else if (event == "onPacket") {
        serv.onPacket = (_onPacket) fn;
    } else if (event == "onClose") {
        serv.onClose = (_onClose) fn;
    } else {
        serv.onConnect = (_onConnect) fn;
    }
}

bool Server::start() {
    return serv.start() == 0;
}

bool Server::listen(std::string host, int port, enum swSocketType type) {
    ListenPort *ls = serv.add_port(type, (char *) host.c_str(), port);
    if (ls == nullptr) {
        return false;
    }

    ports.push_back(ls);
    return true;
}

int Server::send(int session_id, const void *data, uint32_t length) {
    return serv.send(session_id, data, length);
}

ssize_t Server::sendto(const Address &address, const char *__buf, size_t __n, int server_socket_fd) {
    network::Socket *server_socket;
    if (server_socket_fd < 0) {
        server_socket = serv.udp_socket_ipv6 ? serv.udp_socket_ipv6 : serv.udp_socket_ipv4;
    } else {
        server_socket = serv.get_server_socket(server_socket_fd);
    }
    return server_socket->sendto(address, __buf, __n, 0);
}

int Server::close(int session_id, int reset) {
    return serv.close(session_id, reset);
}
