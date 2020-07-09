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

#define SW_SOCK_ASYNC    1
#define SW_SOCK_SYNC     0

#define SW_HTTPS_PROXY_HANDSHAKE_RESPONSE  "HTTP/1.1 200 Connection established"

struct swClient
{
    int id;
    int type;
    long timeout_id; //timeout node id
    int _sock_type;
    int _sock_domain;
    int _protocol;
    enum swFd_type reactor_fdtype;

    uchar active :1;
    uchar async :1;
    uchar keep :1;
    uchar destroyed :1;
    uchar http2 :1;
    uchar sleep :1;
    uchar wait_dns :1;
    uchar shutdow_rw :1;
    uchar shutdown_read :1;
    uchar shutdown_write :1;
    uchar remove_delay :1;
    uchar closed :1;
    uchar high_watermark :1;

    /**
     * one package: length check
     */
    uchar open_length_check :1;
    uchar open_eof_check :1;

    swProtocol protocol;
    swSocks5_proxy *socks5_proxy;
    swHttp_proxy *http_proxy;

    uint32_t reuse_count;

    const char *server_str;
    const char *server_host;
    int server_port;
    void *ptr;
    void *params;

    uint8_t server_strlen;
    double timeout;
    swTimer_node *timer;

    /**
     * signal interruption
     */
    double interrupt_time;

    /**
     * sendto, read only.
     */
    swSocketAddress server_addr;

    /**
     * recvfrom
     */
    swSocketAddress remote_addr;

    swSocket *socket;

    void *object;

    swString *buffer;
    uint32_t wait_length;
    uint32_t input_buffer_size;

    uint32_t buffer_high_watermark;
    uint32_t buffer_low_watermark;

#ifdef SW_USE_OPENSSL
    uchar open_ssl :1;
    uchar ssl_wait_handshake :1;
    SSL_CTX *ssl_context;
    swSSL_option ssl_option;
#endif

    void (*onConnect)(swClient *cli);
    void (*onError)(swClient *cli);
    void (*onReceive)(swClient *cli, const char *data, uint32_t length);
    void (*onClose)(swClient *cli);
    void (*onBufferFull)(swClient *cli);
    void (*onBufferEmpty)(swClient *cli);

    int (*connect)(swClient *cli, const char *host, int port, double _timeout, int sock_flag);
    int (*send)(swClient *cli, const char *data, size_t length, int flags);
    int (*sendfile)(swClient *cli, const char *filename, off_t offset, size_t length);
    int (*recv)(swClient *cli, char *data, int len, int flags);
    int (*close)(swClient *cli);
};

void swClient_init_reactor(swReactor *reactor);
int swClient_create(swClient *cli, enum swSocket_type type, int async);
int swClient_sleep(swClient *cli);
int swClient_wakeup(swClient *cli);
int swClient_shutdown(swClient *cli, int __how);
#ifdef SW_USE_OPENSSL
int swClient_enable_ssl_encrypt(swClient *cli);
int swClient_ssl_handshake(swClient *cli);
int swClient_ssl_verify(swClient *cli, int allow_self_signed);
#endif
void swClient_free(swClient *cli);
//----------------------------------------Stream---------------------------------------
struct swStream
{
    swString *buffer;
    uint8_t cancel;
    int errCode;
    void *private_data;
    void (*response)(swStream *stream, const char *data, uint32_t length);
    swClient client;
};

swStream* swStream_new(const char *dst_host, int dst_port, enum swSocket_type type);
int swStream_send(swStream *stream, const char *data, size_t length);
void swStream_set_protocol(swProtocol *protocol);
void swStream_set_max_length(swStream *stream, uint32_t max_length);
int swStream_recv_blocking(swSocket *sock, void *__buf, size_t __len);
//----------------------------------------Stream End------------------------------------
