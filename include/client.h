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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole_api.h"
#include "swoole_string.h"
#include "swoole_socket.h"
#include "swoole_reactor.h"
#include "swoole_protocol.h"
#include "proxy.h"
#include "ssl.h"

#define SW_HTTPS_PROXY_HANDSHAKE_RESPONSE "HTTP/1.1 200 Connection established"

namespace swoole { namespace network {

class Client {
 public:
    int id = 0;
    enum swSocket_type type;
    long timeout_id = 0;  // timeout node id
    int _sock_type = 0;
    int _sock_domain = 0;
    int _protocol = 0;
    enum swFd_type reactor_fdtype;

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

    /**
     * one package: length check
     */
    bool open_length_check = false;
    bool open_eof_check = false;

    Protocol protocol = {};
    swSocks5_proxy *socks5_proxy = nullptr;
    swHttp_proxy *http_proxy = nullptr;

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

    swString *buffer = nullptr;
    uint32_t wait_length = 0;
    uint32_t input_buffer_size = 0;

    uint32_t buffer_high_watermark = 0;
    uint32_t buffer_low_watermark = 0;

#ifdef SW_USE_OPENSSL
    bool open_ssl = false;
    bool ssl_wait_handshake = false;
    SSL_CTX *ssl_context = nullptr;
    swSSL_option ssl_option = {};
#endif

    void (*onConnect)(Client *cli) = nullptr;
    void (*onError)(Client *cli) = nullptr;
    void (*onReceive)(Client *cli, const char *data, uint32_t length) = nullptr;
    void (*onClose)(Client *cli) = nullptr;
    void (*onBufferFull)(Client *cli) = nullptr;
    void (*onBufferEmpty)(Client *cli) = nullptr;

    int (*connect)(Client *cli, const char *host, int port, double _timeout, int sock_flag) = nullptr;
    ssize_t (*send)(Client *cli, const char *data, size_t length, int flags) = nullptr;
    int (*sendfile)(Client *cli, const char *filename, off_t offset, size_t length) = nullptr;
    ssize_t (*recv)(Client *cli, char *data, size_t length, int flags) = nullptr;

    static void init_reactor(Reactor *reactor);
    Client(enum swSocket_type type, bool async);
    ~Client();

    int sleep();
    int wakeup();
    int shutdown(int __how);
    int close();
    void destroy();
#ifdef SW_USE_OPENSSL
    int enable_ssl_encrypt();
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
    std::function<void(Stream *stream, const char *data, uint32_t length)> response = nullptr;

    int send(const char *data, size_t length);
    void set_max_length(uint32_t max_length);

    inline static Stream *create(const char *dst_host, int dst_port, enum swSocket_type type) {
        Stream *stream = new Stream(dst_host, dst_port, type);
        if (!stream->connected) {
            delete stream;
            return nullptr;
        } else {
            return stream;
        }
    }
    ~Stream();
    static int recv_blocking(Socket *sock, void *__buf, size_t __len);
    static void set_protocol(swProtocol *protocol);

 private:
    Stream(const char *dst_host, int dst_port, enum swSocket_type type);
};
//----------------------------------------Stream End------------------------------------

}}
