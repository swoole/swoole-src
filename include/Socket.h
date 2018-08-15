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
    bool shutdown(int how);
    bool close();
    ssize_t send(const void *__buf, size_t __n);
    ssize_t peek(void *__buf, size_t __n);
    ssize_t recv(void *__buf, size_t __n);
    ssize_t recv_all(void *__buf, size_t __n);
    ssize_t send_all(const void *__buf, size_t __n);
    Socket* accept();
    void resume();
    void yield();
    bool bind(std::string address, int port = 0);
    std::string resolve(std::string host);
    bool listen(int backlog = 0);
    bool sendfile(char *filename, off_t offset, size_t length);
    int sendto(char *address, int port, char *data, int len);
    int recvfrom(void *__buf, size_t __n, char *address, int *port = nullptr);

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
    inline void init()
    {
        _cid = 0;
        _timeout = 0;
        _port = 0;
        errCode = 0;
        errMsg = nullptr;
        timer = nullptr;
        bind_port = 0;
        _backlog = 0;

        shutdow_rw = 0;
        shutdown_read = 0;
        shutdown_write = 0;

#ifdef SW_USE_OPENSSL
        open_ssl = 0;
        ssl_wait_handshake = 0;
        ssl_context = NULL;
        ssl_option = {0};
#endif
    }

    inline bool wait_events(int events)
    {
        if (reactor->add(reactor, socket->fd, SW_FD_CORO_SOCKET | events) < 0)
        {
            _error: errCode = errno;
            return false;
        }
        else
        {
            return true;
        }
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
    enum swSocket_type _type;
    int _sock_type;
    int _sock_domain;
    double _timeout;
    int _backlog;
    int errCode;
    const char *errMsg;
    uint32_t http2 :1;
    uint32_t shutdow_rw :1;
    uint32_t shutdown_read :1;
    uint32_t shutdown_write :1;

#ifdef SW_USE_OPENSSL
    uint8_t open_ssl :1;
    uint8_t ssl_wait_handshake :1;
    SSL_CTX *ssl_context;
    swSSL_option ssl_option;
#endif
};

};
