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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole_api.h"
#include "swoole_string.h"
#include "swoole_socket.h"
#include "swoole_reactor.h"
#include "swoole_protocol.h"
#include "swoole_proxy.h"

#define SW_HTTPS_PROXY_HANDSHAKE_RESPONSE "HTTP/1.1 200 Connection established"

namespace swoole {
namespace network {

class Client {
  public:
    int id = 0;
    long timeout_id = 0;  // timeout node id
    int _sock_type = 0;
    int _sock_domain = 0;
    int _protocol = 0;
    FdType fd_type;
    bool active = false;
    bool async = false;
    bool keep = false;
    bool destroyed = false;
    bool http2 = false;
    bool sleep_ = false;
    bool wait_dns = false;
    bool shutdow_rw = false;
    bool shutdown_read = false;
    bool shutdown_write = false;
    bool remove_delay = false;
    bool closed = false;
    bool high_watermark = false;
    bool async_connect = false;

    /**
     * one package: length check
     */
    bool open_length_check = false;
    bool open_eof_check = false;

    Protocol protocol = {};
    Socks5Proxy *socks5_proxy = nullptr;
    HttpProxy *http_proxy = nullptr;

    uint32_t reuse_count = 0;

    const char *server_str = nullptr;
    const char *server_host = nullptr;
    int server_port = 0;
    void *ptr = nullptr;
    void *params = nullptr;

    uint8_t server_strlen = 0;
    double timeout = 0;
    TimerNode *timer = nullptr;

    /**
     * signal interruption
     */
    double interrupt_time = 0;

    /**
     * sendto, read only.
     */
    Address server_addr = {};

    /**
     * recvfrom
     */
    Address remote_addr = {};

    Socket *socket;

    void *object = nullptr;

    String *buffer = nullptr;
    uint32_t wait_length = 0;
    uint32_t input_buffer_size = 0;

    uint32_t buffer_high_watermark = 0;
    uint32_t buffer_low_watermark = 0;

#ifdef SW_USE_OPENSSL
    bool open_ssl = false;
    bool ssl_wait_handshake = false;
    std::shared_ptr<SSLContext> ssl_context = nullptr;
#endif

    std::function<void (Client *cli)> onConnect = nullptr;
    std::function<void (Client *cli)> onError = nullptr;
    std::function<void (Client *cli, const char *, size_t)> onReceive = nullptr;
    std::function<void (Client *cli)> onClose = nullptr;
    std::function<void (Client *cli)> onBufferFull = nullptr;
    std::function<void (Client *cli)> onBufferEmpty = nullptr;

    int (*connect)(Client *cli, const char *host, int port, double _timeout, int sock_flag) = nullptr;
    ssize_t (*send)(Client *cli, const char *data, size_t length, int flags) = nullptr;
    int (*sendfile)(Client *cli, const char *filename, off_t offset, size_t length) = nullptr;
    ssize_t (*recv)(Client *cli, char *data, size_t length, int flags) = nullptr;

    static void init_reactor(Reactor *reactor);
    Client(SocketType type, bool async);
    ~Client();

    void set_http_proxy(const std::string &host, int port) {
        http_proxy = new swoole::HttpProxy;
        http_proxy->proxy_host = host;
        http_proxy->proxy_port = port;
    }

    Socket *get_socket() {
        return socket;
    }

    int sleep();
    int wakeup();
    int shutdown(int __how);
    int close();
    void destroy();
    int socks5_handshake(const char *recv_data, size_t length);
#ifdef SW_USE_OPENSSL
    int enable_ssl_encrypt();
#ifdef SW_SUPPORT_DTLS
    void enable_dtls();
#endif
    int ssl_handshake();
    int ssl_verify(int allow_self_signed);
#endif
};

//----------------------------------------Stream---------------------------------------
class Stream {
  public:
    String *buffer = nullptr;
    Client client;
    bool connected = false;
    bool cancel = false;
    int errCode = 0;
    void *private_data = nullptr;
    void *private_data_2 = nullptr;
    long private_data_fd = -1;

    std::function<void(Stream *stream, const char *data, uint32_t length)> response = nullptr;

    int send(const char *data, size_t length);
    void set_max_length(uint32_t max_length);

    inline static Stream *create(const char *dst_host, int dst_port, SocketType type) {
        Stream *stream = new Stream(dst_host, dst_port, type);
        if (!stream->connected) {
            delete stream;
            return nullptr;
        } else {
            return stream;
        }
    }
    ~Stream();
    static ssize_t recv_blocking(Socket *sock, void *__buf, size_t __len);
    static void set_protocol(Protocol *protocol);

  private:
    Stream(const char *dst_host, int dst_port, SocketType type);
};
//----------------------------------------Stream End------------------------------------

class SyncClient {
  protected:
    Client client;
    bool connected = false;
    bool created;
    bool async = false;
    SocketType type;

  public:
    SyncClient(SocketType _type, bool _async = false) : client(_type, _async), async(_async), type(_type) {
        created = client.socket != nullptr;
    }

    bool connect(const char *host, int port, double timeout = -1) {
        if (connected || !created) {
            return false;
        }
        if (client.connect(&client, host, port, timeout, client.socket->is_dgram()) < 0) {
            return false;
        }
        connected = true;
        return true;
    }

#ifdef SW_USE_OPENSSL
    bool enable_ssl_encrypt() {
        if (client.enable_ssl_encrypt() < 0 || client.ssl_handshake() < 0) {
            return false;
        } else {
            return true;
        }
    }
#endif

    ssize_t send(const std::string &data) {
        return client.send(&client, data.c_str(), data.length(), 0);
    }

    ssize_t send(const char *buf, size_t len) {
        return client.send(&client, buf, len, 0);
    }

    ssize_t recv(char *buf, size_t len) {
        return client.recv(&client, buf, len, 0);
    }

    bool close() {
        if (!created || client.closed) {
            return false;
        }
        client.close();
        created = false;
        return true;
    }

    virtual ~SyncClient() {
        if (created) {
            close();
        }
    }
};

class AsyncClient : public SyncClient {
  protected:
    std::function<void(AsyncClient *)> _onConnect = nullptr;
    std::function<void(AsyncClient *)> _onError = nullptr;
    std::function<void(AsyncClient *)> _onClose = nullptr;
    std::function<void(AsyncClient *, const char *data, size_t length)> _onReceive = nullptr;

  public:
    AsyncClient(SocketType _type) : SyncClient(_type, true) {}

    bool connect(const char *host, int port, double timeout = -1) {
        client.object = this;
        client.onConnect = [](Client *cli) {
            AsyncClient *ac = (AsyncClient *) cli->object;
            ac->_onConnect(ac);
        };
        client.onError = [](Client *cli) {
            AsyncClient *ac = (AsyncClient *) cli->object;
            ac->_onError(ac);
        };
        client.onClose = [](Client *cli) {
            AsyncClient *ac = (AsyncClient *) cli->object;
            ac->_onClose(ac);
        };
        client.onReceive = [](Client *cli, const char *data, size_t length) {
            AsyncClient *ac = (AsyncClient *) cli->object;
            ac->_onReceive(ac, data, length);
        };
        return SyncClient::connect(host, port, timeout);
    }

    void on_connect(std::function<void(AsyncClient *)> fn) {
        _onConnect = fn;
    }

    void on_error(std::function<void(AsyncClient *)> fn) {
        _onError = fn;
    }

    void on_close(std::function<void(AsyncClient *)> fn) {
        _onClose = fn;
    }

    void on_receive(std::function<void(AsyncClient *, const char *data, size_t length)> fn) {
        _onReceive = fn;
    }
};

}  // namespace network
}  // namespace swoole
