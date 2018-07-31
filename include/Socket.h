#pragma once

#include "swoole.h"
#include <string>

namespace swoole {

class Socket {
public:
    Socket(enum swSocket_type type);
    Socket(int _fd, Socket *sock);
    ~Socket();
    bool connect(std::string host, int port, int flags = 0);
    bool close();
    ssize_t send(const void *__buf, size_t __n, int __flags = 0);
    ssize_t recv(void *__buf, size_t __n, int __flags = 0);
    Socket* accept();
    void resume();
    void yield();
    bool bind(std::string address, int port = 0);
    bool listen(int backlog = 0);

    void setTimeout(double timeout)
    {
        _timeout = timeout;
    }

    swTimer_node *timer;
    swReactor *reactor;
    std::string _host;
    std::string bind_address;
    int bind_port;
    int _port;
    int fd;
    int _cid;
    swConnection *socket;
    int _sock_type;
    int _sock_domain;
    double _timeout;
    int _backlog;
    int errCode;
    const char *errMsg;
};

};
