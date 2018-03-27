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

#ifndef SW_CLIENT_H_
#define SW_CLIENT_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "buffer.h"
#include "Connection.h"

#define SW_SOCK_ASYNC    1
#define SW_SOCK_SYNC     0

#define SW_HTTPS_PROXY_HANDSHAKE_RESPONSE  "HTTP/1.1 200 Connection established"

enum swClient_pipe_flag
{
    SW_CLIENT_PIPE_TCP_SESSION = 1,
};

enum swHttp_proxy_state
{
    SW_HTTP_PROXY_STATE_WAIT = 0,
    SW_HTTP_PROXY_STATE_HANDSHAKE,
    SW_HTTP_PROXY_STATE_READY,
};

struct _http_proxy
{
    uint8_t state;
    int proxy_port;
    char *proxy_host;
    char *user;
    char *password;
    int l_user;
    int l_password;
    char *target_host;
    int target_port;
    char buf[600];
};

typedef struct _swClient
{
    int id;
    int type;
    long timeout_id; //timeout node id
    int _sock_type;
    int _sock_domain;
    int _protocol;
    int reactor_fdtype;

    int _redirect_to_file;
    int _redirect_to_socket;
    int _redirect_to_session;

    uint32_t async :1;
    uint32_t keep :1;
    uint32_t released :1;
    uint32_t destroyed :1;
    uint32_t redirect :1;
    uint32_t http2 :1;
    uint32_t sleep :1;
    uint32_t wait_dns :1;
    uint32_t shutdow_rw :1;
    uint32_t shutdown_read :1;
    uint32_t shutdown_write :1;

    /**
     * one package: length check
     */
    uint32_t open_length_check :1;
    uint32_t open_eof_check :1;

    swProtocol protocol;
    struct _swSocks5 *socks5_proxy;
    struct _http_proxy* http_proxy;

    uint32_t reuse_count;

    char *server_str;
    char *server_host;
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

    swConnection *socket;

    /**
     * reactor
     */
    swReactor *reactor;

    void *object;

    swString *buffer;
    uint32_t wait_length;
    uint32_t buffer_input_size;

    uint32_t buffer_high_watermark;
    uint32_t buffer_low_watermark;

#ifdef SW_USE_OPENSSL
    uint8_t open_ssl :1;
    uint8_t ssl_wait_handshake :1;
    SSL_CTX *ssl_context;
    swSSL_option ssl_option;
#endif

    void (*onConnect)(struct _swClient *cli);
    void (*onError)(struct _swClient *cli);
    void (*onReceive)(struct _swClient *cli, char *data, uint32_t length);
    void (*onClose)(struct _swClient *cli);
    void (*onBufferFull)(struct _swClient *cli);
    void (*onBufferEmpty)(struct _swClient *cli);

    int (*connect)(struct _swClient *cli, char *host, int port, double _timeout, int sock_flag);
    int (*send)(struct _swClient *cli, char *data, int length, int flags);
    int (*sendfile)(struct _swClient *cli, char *filename, off_t offset, size_t length);
    int (*recv)(struct _swClient *cli, char *data, int len, int flags);
    int (*pipe)(struct _swClient *cli, int write_fd, int is_session_id);
    int (*close)(struct _swClient *cli);

} swClient;

int swClient_create(swClient *cli, int type, int async);
int swClient_sleep(swClient *cli);
int swClient_wakeup(swClient *cli);
int swClient_shutdown(swClient *cli, int __how);
#ifdef SW_USE_OPENSSL
int swClient_enable_ssl_encrypt(swClient *cli);
int swClient_ssl_handshake(swClient *cli);
int swClient_ssl_verify(swClient *cli, int allow_self_signed);
#endif
void swClient_free(swClient *cli);

typedef struct
{
    uint8_t num;
    struct
    {
        uint8_t length;
        char address[16];
    } hosts[SW_DNS_HOST_BUFFER_SIZE];
} swDNSResolver_result;

int swDNSResolver_request(char *domain, void (*callback)(char *, swDNSResolver_result *, void *), void *data);
int swDNSResolver_free();

//----------------------------------------Stream---------------------------------------
typedef struct _swStream
{
    swString *buffer;
    uint32_t session_id;
    uint8_t cancel;
    void (*response)(struct _swStream *stream, char *data, uint32_t length);
    swClient client;
} swStream;

swStream* swStream_new(char *dst_host, int dst_port, int type);
int swStream_send(swStream *stream, char *data, size_t length);
void swStream_set_protocol(swProtocol *protocol);
void swStream_set_max_length(swStream *stream, uint32_t max_length);
int swStream_recv_blocking(int fd, void *__buf, size_t __len);
//----------------------------------------Stream End------------------------------------

#ifdef __cplusplus
}
#endif

#endif /* SW_CLIENT_H_ */
