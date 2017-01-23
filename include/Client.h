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

#include "buffer.h"
#include "Connection.h"

#define SW_SOCK_ASYNC    1
#define SW_SOCK_SYNC     0

enum swClient_pipe_flag
{
    SW_CLIENT_PIPE_TCP_SESSION = 1,
};

typedef struct _swClient
{
    int id;
    int type;
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

    /**
     * one package: length check
     */
    uint32_t open_length_check :1;
    uint32_t open_eof_check :1;

    swProtocol protocol;
    struct _swSocks5 *socks5_proxy;

    uint32_t reuse_count;

    char *server_str;
    void *ptr;
    void *params;

    uint8_t server_strlen;
    double timeout;

    /**
     * sendto, read only.
     */
    swSocketAddress server_addr;

    /**
     * recvfrom
     */
    swSocketAddress remote_addr;

    swConnection *socket;
    void *object;

    swString *buffer;
    uint32_t wait_length;
    uint32_t buffer_input_size;

    uint32_t buffer_high_watermark;
    uint32_t buffer_low_watermark;

#ifdef SW_USE_OPENSSL
    uint8_t open_ssl :1;
    uint8_t ssl_disable_compress :1;
    uint8_t ssl_wait_handshake :1;
    char *ssl_cert_file;
    char *ssl_key_file;
    SSL_CTX *ssl_context;
    uint8_t ssl_method;
#endif

    void (*onConnect)(struct _swClient *cli);
    void (*onError)(struct _swClient *cli);
    void (*onReceive)(struct _swClient *cli, char *data, uint32_t length);
    void (*onClose)(struct _swClient *cli);
    void (*onBufferFull)(struct _swClient *cli);
    void (*onBufferEmpty)(struct _swClient *cli);

    int (*connect)(struct _swClient *cli, char *host, int port, double _timeout, int sock_flag);
    int (*send)(struct _swClient *cli, char *data, int length, int flags);
    int (*sendfile)(struct _swClient *cli, char *filename, off_t offset);
    int (*recv)(struct _swClient *cli, char *data, int len, int flags);
    int (*pipe)(struct _swClient *cli, int write_fd, int is_session_id);
    int (*close)(struct _swClient *cli);

} swClient;

int swClient_create(swClient *cli, int type, int async);
#ifdef SW_USE_OPENSSL
int swClient_enable_ssl_encrypt(swClient *cli);
int swClient_ssl_handshake(swClient *cli);
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

#endif /* SW_CLIENT_H_ */
