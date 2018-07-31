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
  | Author: shiguangqi  <shiguangqi2008@gmail.com>                       |
  +----------------------------------------------------------------------+
*/

#ifndef SW_CORO_CLIENT_H_
#define SW_CORO_CLIENT_H_

#include "Socket.h"
namespace swoole {

struct Client : Socket
{
    int id;
    int type;
    long timeout_id; //timeout node id
    int _protocol;
    int reactor_fdtype;

    int _redirect_to_file;
    int _redirect_to_socket;
    int _redirect_to_session;

    uint32_t async :1;
    uint32_t keep :1;
    uint32_t destroyed :1;
    uint32_t redirect :1;
    uint32_t http2 :1;
    uint32_t _sleep :1;
    uint32_t shutdow_rw :1;
    uint32_t shutdown_read :1;
    uint32_t shutdown_write :1;
    uint32_t remove_delay :1;

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


    void *object;

    swString *buffer;
    uint32_t buffer_input_size;

    uint32_t buffer_high_watermark;
    uint32_t buffer_low_watermark;

#ifdef SW_USE_OPENSSL
    uint8_t open_ssl :1;
    uint8_t ssl_wait_handshake :1;
    SSL_CTX *ssl_context;
    swSSL_option ssl_option;
#endif

    Client(long type);
    ~Client();
    bool tcp_connect(char *host, int port, int flags);
    bool udp_connect(char *host, int port, int flags);
    int socks5_connect(char *host, int port);
    int tcp_send(char *data, int length, int flags);
    int udp_send(char *data, int length, int flags);
    int tcp_recv(char *data, int length, int flags);
    int udp_recv(char *data, int length, int flags);
    int sendfile(char *filename, off_t offset, size_t length);
    void proxy_check(char *host, int port);
    int pipe(int write_fd, int is_session_id);
    int close();
    int sleep();
    int wakeup();
    int shutdown(int how);
};

int Client_create(Client *cli, int type, int async);
int Client_sleep(Client *cli);
int Client_wakeup(Client *cli);
int Client_shutdown(Client *cli, int __how);
#ifdef SW_USE_OPENSSL
int Client_enable_ssl_encrypt(Client *cli);
int Client_ssl_handshake(Client *cli);
int Client_ssl_verify(Client *cli, int allow_self_signed);
#endif
void Client_free(Client *cli);
int Client_close(Client *cli);

//----------------------------------------Coro Stream---------------------------------------
typedef struct _Stream
{
    swString *buffer;
    uint32_t session_id;
    uint8_t cancel;
    void (*response)(struct _Stream *stream, char *data, uint32_t length);
    Client client;
} Stream;

Stream* Stream_new(char *dst_host, int dst_port, int type);
int Stream_send(Stream *stream, char *data, size_t length);
void Stream_set_protocol(swProtocol *protocol);
void Stream_set_max_length(Stream *stream, uint32_t max_length);
int Stream_recv_blocking(int fd, void *__buf, size_t __len);
//----------------------------------------Coro Stream End------------------------------------

}
#endif /* SW_CORO_CLIENT_H_ */
