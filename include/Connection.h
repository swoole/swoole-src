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
int swConnection_sendfile(swConnection *conn, char *filename);
int swConnection_onSendfile(swConnection *conn, swBuffer_trunk *chunk);
void swConnection_sendfile_destructor(swBuffer_trunk *chunk);
char* swConnection_get_ip(swConnection *conn);
int swConnection_get_port(swConnection *conn);

#ifdef SW_USE_OPENSSL
void swSSL_init(void);
SSL_CTX* swSSL_get_server_context(char *cert_file, char *key_file, int method);
SSL_CTX* swSSL_get_client_context(int method);
void swSSL_free(SSL_CTX* ssl_context);
int swSSL_create(swConnection *conn, SSL_CTX* ssl_context, int flags);
int swSSL_accept(swConnection *conn);
int swSSL_connect(swConnection *conn);
void swSSL_close(swConnection *conn);
ssize_t swSSL_recv(swConnection *conn, void *__buf, size_t __n);
ssize_t swSSL_send(swConnection *conn, void *__buf, size_t __n);

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
    SW_TLSv1_1_METHOD,
    SW_TLSv1_1_SERVER_METHOD,
    SW_TLSv1_1_CLIENT_METHOD,
    SW_TLSv1_2_METHOD,
    SW_TLSv1_2_SERVER_METHOD,
    SW_TLSv1_2_CLIENT_METHOD,
    SW_DTLSv1_METHOD,
    SW_DTLSv1_SERVER_METHOD,
    SW_DTLSv1_CLIENT_METHOD,
};

#endif

/**
 * Receive data from connection
 */
static sw_inline ssize_t swConnection_recv(swConnection *conn, void *__buf, size_t __n, int __flags)
{
#ifdef SW_USE_OPENSSL
    if (conn->ssl)
    {
        return swSSL_recv(conn, __buf, __n);
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
	case ECONNRESET:
	case EPIPE:
	case ENOTCONN:
	case ETIMEDOUT:
	case ECONNREFUSED:
	case ENETDOWN:
	case ENETUNREACH:
	case EHOSTDOWN:
	case EHOSTUNREACH:
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


#endif /* SW_CONNECTION_H_ */
