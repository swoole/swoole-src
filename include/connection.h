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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#ifndef SW_CONNECTION_H_
#define SW_CONNECTION_H_

SW_EXTERN_C_BEGIN

#include "buffer.h"

#ifdef SW_USE_OPENSSL

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/ossl_typ.h>

#define SW_SSL_BUFFER      1
#define SW_SSL_CLIENT      2

typedef struct _swSSL_option
{
    char *cert_file;
    char *key_file;
    char *passphrase;
    char *client_cert_file;
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    uint8_t disable_tls_host_name :1;
    char *tls_host_name;
#endif
    char *cafile;
    char *capath;
    uint8_t verify_depth;
    uint8_t method;
    uint8_t disable_compress :1;
    uint8_t verify_peer :1;
    uint8_t allow_self_signed :1;
} swSSL_option;

#endif

int swConnection_buffer_send(swConnection *conn);

int swConnection_sendfile(swConnection *conn, char *filename, off_t offset, size_t length);
int swConnection_onSendfile(swConnection *conn, swBuffer_chunk *chunk);
void swConnection_sendfile_destructor(swBuffer_chunk *chunk);
const char* swConnection_get_ip(swConnection *conn);
int swConnection_get_port(swConnection *conn);

static sw_inline swString *swConnection_get_buffer(swConnection *conn)
{
    swString *buffer = conn->recv_buffer;
    if (buffer == NULL)
    {
        buffer = swString_new(SW_BUFFER_SIZE_BIG);
        //alloc memory failed.
        if (!buffer)
        {
            return NULL;
        }
        conn->recv_buffer = buffer;
    }
    return buffer;
}

static sw_inline void swConnection_free_buffer(swConnection *conn)
{
    if (conn->recv_buffer)
    {
        swString_free(conn->recv_buffer);
        conn->recv_buffer = NULL;
    }
}

#ifdef SW_USE_OPENSSL
enum swSSLState
{
    SW_SSL_STATE_HANDSHAKE    = 0,
    SW_SSL_STATE_READY        = 1,
    SW_SSL_STATE_WAIT_STREAM  = 2,
};

enum swSSLMethod
{
    SW_SSLv23_METHOD = 0,
    SW_SSLv3_METHOD,
    SW_SSLv3_SERVER_METHOD,
    SW_SSLv3_CLIENT_METHOD,
    SW_SSLv23_SERVER_METHOD,
    SW_SSLv23_CLIENT_METHOD,
    SW_TLSv1_METHOD,
    SW_TLSv1_SERVER_METHOD,
    SW_TLSv1_CLIENT_METHOD,
#ifdef TLS1_1_VERSION
    SW_TLSv1_1_METHOD,
    SW_TLSv1_1_SERVER_METHOD,
    SW_TLSv1_1_CLIENT_METHOD,
#endif
#ifdef TLS1_2_VERSION
    SW_TLSv1_2_METHOD,
    SW_TLSv1_2_SERVER_METHOD,
    SW_TLSv1_2_CLIENT_METHOD,
#endif
    SW_DTLSv1_METHOD,
    SW_DTLSv1_SERVER_METHOD,
    SW_DTLSv1_CLIENT_METHOD,
};

typedef struct
{
    uint32_t http :1;
    uint32_t http_v2 :1;
    uint32_t prefer_server_ciphers :1;
    uint32_t session_tickets :1;
    uint32_t stapling :1;
    uint32_t stapling_verify :1;
    char *ciphers;
    char *ecdh_curve;
    char *session_cache;
    char *dhparam;
} swSSL_config;

void swSSL_init(void);
void swSSL_init_thread_safety();
int swSSL_server_set_cipher(SSL_CTX* ssl_context, swSSL_config *cfg);
void swSSL_server_http_advise(SSL_CTX* ssl_context, swSSL_config *cfg);
SSL_CTX* swSSL_get_context(swSSL_option *option);
void swSSL_free_context(SSL_CTX* ssl_context);
int swSSL_create(swConnection *conn, SSL_CTX* ssl_context, int flags);
int swSSL_set_client_certificate(SSL_CTX *ctx, char *cert_file, int depth);
int swSSL_set_capath(swSSL_option *cfg, SSL_CTX *ctx);
int swSSL_check_host(swConnection *conn, char *tls_host_name);
int swSSL_get_client_certificate(SSL *ssl, char *buffer, size_t length);
int swSSL_verify(swConnection *conn, int allow_self_signed);
int swSSL_accept(swConnection *conn);
int swSSL_connect(swConnection *conn);
void swSSL_close(swConnection *conn);
ssize_t swSSL_recv(swConnection *conn, void *__buf, size_t __n);
ssize_t swSSL_send(swConnection *conn, const void *__buf, size_t __n);
int swSSL_sendfile(swConnection *conn, int fd, off_t *offset, size_t size);
#endif

/**
 * Receive data from connection
 */
static sw_inline ssize_t swConnection_recv(swConnection *conn, void *__buf, size_t __n, int __flags)
{
    ssize_t total_bytes = 0;

    do
    {
#ifdef SW_USE_OPENSSL
        if (conn->ssl)
        {
            ssize_t retval = 0;
            while ((size_t) total_bytes < __n)
            {
                retval = swSSL_recv(conn, ((char*)__buf) + total_bytes, __n - total_bytes);
                if (retval <= 0)
                {
                    if (total_bytes == 0)
                    {
                        total_bytes = retval;
                    }
                    break;
                }
                else
                {
                    total_bytes += retval;
                    if (!(conn->nonblock || (__flags & MSG_WAITALL)))
                    {
                        break;
                    }
                }
            }
        }
        else
#endif
        {
            total_bytes = recv(conn->fd, __buf, __n, __flags);
        }
    }
    while (total_bytes < 0 && errno == EINTR);

#ifdef SW_DEBUG
    if (total_bytes > 0)
    {
        conn->total_recv_bytes += total_bytes;
    }
#endif

    swTraceLog(SW_TRACE_SOCKET, "recv %ld/%ld bytes, errno=%d", total_bytes, __n, errno);

    return total_bytes;
}

/**
 * Send data to connection
 */
static sw_inline ssize_t swConnection_send(swConnection *conn, const void *__buf, size_t __n, int __flags)
{
    ssize_t retval;

    do
    {
#ifdef SW_USE_OPENSSL
        if (conn->ssl)
        {
            retval = swSSL_send(conn, __buf, __n);
        }
        else
#endif
        {
            retval = send(conn->fd, __buf, __n, __flags);
        }
    }
    while (retval < 0 && errno == EINTR);

#ifdef SW_DEBUG
    if (retval > 0)
    {
        conn->total_send_bytes += retval;
    }
#endif

    swTraceLog(SW_TRACE_SOCKET, "send %ld/%ld bytes, errno=%d", retval, __n, errno);

    return retval;
}


/**
 * Receive data from connection
 */
static sw_inline ssize_t swConnection_peek(swConnection *conn, void *__buf, size_t __n, int __flags)
{
    ssize_t retval;
    __flags |= MSG_PEEK;
    do
    {
#ifdef SW_USE_OPENSSL
        if (conn->ssl)
        {
            retval = SSL_peek(conn->ssl, __buf, __n);
        }
        else
#endif
        {
            retval = recv(conn->fd, __buf, __n, __flags);
        }
    }
    while (retval < 0 && errno == EINTR);

    swTraceLog(SW_TRACE_SOCKET, "peek %ld/%ld bytes, errno=%d", retval, __n, errno);

    return retval;
}

static sw_inline int swConnection_error(int err)
{
    switch (err)
    {
    case EFAULT:
        abort();
        return SW_ERROR;
    case EBADF:
    case ECONNRESET:
#ifdef __CYGWIN__
    case ECONNABORTED:
#endif
    case EPIPE:
    case ENOTCONN:
    case ETIMEDOUT:
    case ECONNREFUSED:
    case ENETDOWN:
    case ENETUNREACH:
    case EHOSTDOWN:
    case EHOSTUNREACH:
    case SW_ERROR_SSL_BAD_CLIENT:
        return SW_CLOSE;
    case EAGAIN:
#ifdef HAVE_KQUEUE
    case ENOBUFS:
#endif
    case 0:
        return SW_WAIT;
    default:
        return SW_ERROR;
    }
}

SW_EXTERN_C_END

#endif /* SW_CONNECTION_H_ */
