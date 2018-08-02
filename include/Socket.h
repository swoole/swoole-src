#pragma once

#include "swoole.h"
#include "Connection.h"
#include <string>

namespace swoole {

class Socket {
public:
    Socket(enum swSocket_type type);
    Socket(int _fd, Socket *sock);
    ~Socket();
    bool connect(std::string host, int port, int flags = 0);
    bool close();
    ssize_t send(const void *__buf, size_t __n);
    ssize_t peek(void *__buf, size_t __n);
    ssize_t recv(void *__buf, size_t __n);
    ssize_t recv_waitall(void *__buf, size_t __n);
    Socket* accept();
    void resume();
    void yield();
    bool bind(std::string address, int port = 0);
    std::string resolve(std::string host);
    bool listen(int backlog = 0);
    bool sendfile(char *filename, off_t offset, size_t length);

    void setTimeout(double timeout)
    {
        _timeout = timeout;
    }

#ifdef SW_USE_OPENSSL
    bool ssl_handshake();
    bool enable_ssl_encrypt();
    int ssl_verify(bool allow_self_signed);
#endif

protected:
    void init()
    {
        _cid = 0;
        _timeout = 0;
        _port = 0;
        errCode = 0;
        errMsg = nullptr;
        timer = nullptr;
        bind_port = 0;
        _backlog = 0;
#ifdef SW_USE_OPENSSL
        open_ssl = 0;
        ssl_wait_handshake = 0;
        ssl_context = NULL;
        ssl_option = {0};
#endif
    }

public:
    swTimer_node *timer;
    swReactor *reactor;
    std::string _host;
    std::string bind_address;
    int bind_port;
    int _port;
    int _cid;
    swConnection *socket;
    int _sock_type;
    int _sock_domain;
    double _timeout;
    int _backlog;
    int errCode;
    const char *errMsg;
    uint32_t http2 :1;

#ifdef SW_USE_OPENSSL
    uint8_t open_ssl :1;
    uint8_t ssl_wait_handshake :1;
    SSL_CTX *ssl_context;
    swSSL_option ssl_option;
#endif
};

};
