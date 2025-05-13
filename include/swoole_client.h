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
    std::unique_ptr<Socks5Proxy> socks5_proxy = nullptr;
    std::unique_ptr<HttpProxy> http_proxy = nullptr;

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
     * for connect()
     */
    Address server_addr = {};

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

    std::function<void(Client *cli)> onConnect = nullptr;
    std::function<void(Client *cli)> onError = nullptr;
    std::function<void(Client *cli, const char *, size_t)> onReceive = nullptr;
    std::function<void(Client *cli)> onClose = nullptr;
    std::function<void(Client *cli)> onBufferFull = nullptr;
    std::function<void(Client *cli)> onBufferEmpty = nullptr;

    int (*connect)(Client *cli, const char *host, int port, double _timeout, int sock_flag) = nullptr;
    ssize_t (*send)(Client *cli, const char *data, size_t length, int flags) = nullptr;
    int (*sendfile)(Client *cli, const char *filename, off_t offset, size_t length) = nullptr;
    ssize_t (*recv)(Client *cli, char *data, size_t length, int flags) = nullptr;

    static void init_reactor(Reactor *reactor);
    Client(SocketType _type, bool async);
    ~Client();

    Socket *get_socket() {
        return socket;
    }

    SocketType get_socket_type() const {
        return socket->socket_type;
    }

    const std::string *get_http_proxy_host_name() const {
#ifdef SW_USE_OPENSSL
        if (ssl_context && !ssl_context->tls_host_name.empty()) {
            return &ssl_context->tls_host_name;
        }
#endif
        return &http_proxy->target_host;
    }

    int bind(const std::string &addr, int port);
    int sleep();
    int wakeup();
    int shutdown(int _how);
    int close();
    int socks5_handshake(const char *recv_data, size_t length);
#ifdef SW_USE_OPENSSL
    int enable_ssl_encrypt();
#ifdef SW_SUPPORT_DTLS
    void enable_dtls();
#endif
    int ssl_handshake();
    int ssl_verify(int allow_self_signed);

    bool set_ssl_key_file(const std::string &file) {
        return ssl_context->set_key_file(file);
    }

    void set_socks5_proxy(const std::string &host, int port, const std::string &user = "", const std::string &pwd = "");
    void set_http_proxy(const std::string &host, int port, const std::string &user = "", const std::string &pwd = "");

    bool set_ssl_cert_file(const std::string &file) {
        return ssl_context->set_cert_file(file);
    }

    void set_ssl_cafile(const std::string &file) {
        ssl_context->cafile = file;
    }

    void set_ssl_capath(const std::string &path) {
        ssl_context->capath = path;
    }

    void set_ssl_passphrase(const std::string &str) {
        ssl_context->passphrase = str;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    void set_tls_host_name(const std::string &str) {
        ssl_context->tls_host_name = str;
        // if user set empty ssl_host_name, disable it, otherwise the underlying may set it automatically
        ssl_context->disable_tls_host_name = ssl_context->tls_host_name.empty();
    }
#endif

    void set_ssl_dhparam(const std::string &file) {
        ssl_context->dhparam = file;
    }

    void set_ssl_ecdh_curve(const std::string &str) {
        ssl_context->ecdh_curve = str;
    }

    void set_ssl_protocols(long protocols) {
        ssl_context->protocols = protocols;
    }

    void set_ssl_disable_compress(bool value) {
        ssl_context->disable_compress = value;
    }

    void set_ssl_verify_peer(bool value) {
        ssl_context->verify_peer = value;
    }

    void set_ssl_allow_self_signed(bool value) {
        ssl_context->allow_self_signed = value;
    }

    void set_ssl_verify_depth(uint8_t value) {
        ssl_context->verify_depth = value;
    }

    void set_ssl_ciphers(const std::string &str) {
        ssl_context->ciphers = str;
    }

#ifdef OPENSSL_IS_BORINGSSL
    void set_ssl_grease(uint8_t value) {
        ssl_context->grease = value;
    }
#endif

    const std::string &get_ssl_cert_file() {
        return ssl_context->cert_file;
    }

    const std::string &get_ssl_key_file() {
        return ssl_context->key_file;
    }
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

    static inline Stream *create(const char *dst_host, int dst_port, SocketType type) {
        auto *stream = new Stream(dst_host, dst_port, type);
        if (!stream->connected) {
            delete stream;
            return nullptr;
        } else {
            return stream;
        }
    }
    ~Stream();
    static ssize_t recv_sync(Socket *sock, void *_buf, size_t _len);
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
    explicit SyncClient(SocketType _type, bool _async = false) : client(_type, _async), async(_async), type(_type) {
        created = client.socket != nullptr;
    }

    virtual bool connect(const char *host, int port, double timeout = -1) {
        if (connected || !created) {
            return false;
        }
        if (client.connect(&client, host, port, timeout, client.socket->is_dgram()) < 0) {
            return false;
        }
        connected = true;
        return true;
    }

    void set_stream_protocol() {
        client.open_length_check = true;
        Stream::set_protocol(&client.protocol);
    }

    void set_package_max_length(uint32_t max_length) {
        client.protocol.package_max_length = max_length;
    }

#ifdef SW_USE_OPENSSL
    bool enable_ssl_encrypt() {
        if (client.enable_ssl_encrypt() < 0) {
            return false;
        }
        if (connected) {
            return client.ssl_handshake() == SW_OK;
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

    bool sendfile(const char *filename, off_t offset = 0, size_t length = 0) {
        return client.sendfile(&client, filename, offset, length) == SW_OK;
    }

    ssize_t recv(char *buf, size_t len, int flags = 0) {
        return client.recv(&client, buf, len, flags);
    }

    bool close() {
        if (!created || client.closed) {
            return false;
        }
        client.close();
        created = false;
        return true;
    }

    Client *get_client() {
        return &client;
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
    explicit AsyncClient(SocketType _type) : SyncClient(_type, true) {}

    bool connect(const char *host, int port, double timeout = -1) override {
        client.object = this;
        client.onConnect = [](Client *cli) {
            auto *ac = (AsyncClient *) cli->object;
            ac->_onConnect(ac);
        };
        client.onError = [](Client *cli) {
            auto *ac = (AsyncClient *) cli->object;
            ac->_onError(ac);
        };
        client.onClose = [](Client *cli) {
            auto *ac = (AsyncClient *) cli->object;
            ac->_onClose(ac);
        };
        client.onReceive = [](Client *cli, const char *data, size_t length) {
            auto *ac = (AsyncClient *) cli->object;
            ac->_onReceive(ac, data, length);
        };
        return SyncClient::connect(host, port, timeout);
    }

    void on_connect(const std::function<void(AsyncClient *)> &fn) {
        _onConnect = fn;
    }

    void on_error(const std::function<void(AsyncClient *)> &fn) {
        _onError = fn;
    }

    void on_close(const std::function<void(AsyncClient *)> &fn) {
        _onClose = fn;
    }

    void on_receive(const std::function<void(AsyncClient *, const char *data, size_t length)> &fn) {
        _onReceive = fn;
    }
};

}  // namespace network
}  // namespace swoole
