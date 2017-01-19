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

#ifdef __cplusplus
extern "C" {
#endif

#include "buffer.h"

#ifdef SW_USE_OPENSSL

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SW_SSL_BUFFER      1
#define SW_SSL_CLIENT      2

#endif

int swConnection_buffer_send(swConnection *conn);

swString* swConnection_get_string_buffer(swConnection *conn);
void swConnection_clear_string_buffer(swConnection *conn);
swBuffer_trunk* swConnection_get_out_buffer(swConnection *conn, uint32_t type);
swBuffer_trunk* swConnection_get_in_buffer(swConnection *conn);
int swConnection_sendfile(swConnection *conn, char *filename, off_t offset);
int swConnection_onSendfile(swConnection *conn, swBuffer_trunk *chunk);
void swConnection_sendfile_destructor(swBuffer_trunk *chunk);
char* swConnection_get_ip(swConnection *conn);
int swConnection_get_port(swConnection *conn);

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
} swSSL_config;

void swSSL_init(void);
int swSSL_server_set_cipher(SSL_CTX* ssl_context, swSSL_config *cfg);
void swSSL_server_http_advise(SSL_CTX* ssl_context, swSSL_config *cfg);
SSL_CTX* swSSL_get_context(int method, char *cert_file, char *key_file);
void swSSL_free_context(SSL_CTX* ssl_context);
int swSSL_create(swConnection *conn, SSL_CTX* ssl_context, int flags);
int swSSL_set_client_certificate(SSL_CTX *ctx, char *cert_file, int depth);
int swSSL_get_client_certificate(SSL *ssl, char *buffer, size_t length);
int swSSL_verify(swConnection *conn, int allow_self_signed);
int swSSL_accept(swConnection *conn);
int swSSL_connect(swConnection *conn);
void swSSL_close(swConnection *conn);
ssize_t swSSL_recv(swConnection *conn, void *__buf, size_t __n);
ssize_t swSSL_send(swConnection *conn, void *__buf, size_t __n);
#endif

/**
 * Receive data from connection
 */
static sw_inline ssize_t swConnection_recv(swConnection *conn, void *__buf, size_t __n, int __flags)
{
#ifdef SW_USE_OPENSSL
    if (conn->ssl)
    {
        int ret = 0;
        int written = 0;

        while(written < __n)
        {
            ret = swSSL_recv(conn, __buf + written, __n - written);
            if (__flags & MSG_WAITALL)
            {
                if (ret <= 0)
                {
                    return ret;
                }
                else
                {
                    written += ret;
                }
            }
            else
            {
                return ret;
            }
        }

        return written;
    }
    else
    {
        return recv(conn->fd, __buf, __n, __flags);
    }
#else
    return recv(conn->fd, __buf, __n, __flags);
#endif
}

/**
 * Send data to connection
 */
static sw_inline int swConnection_send(swConnection *conn, void *__buf, size_t __n, int __flags)
{
#ifdef SW_USE_OPENSSL
    if (conn->ssl)
    {
        return swSSL_send(conn, __buf, __n);
    }
    else
    {
        return send(conn->fd, __buf, __n, __flags);
    }
#else
    return send(conn->fd, __buf, __n, __flags);
#endif
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

#ifdef __cplusplus
}
#endif

#endif /* SW_CONNECTION_H_ */
