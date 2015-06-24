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
char* swConnection_get_ip(swConnection *conn);
int swConnection_get_port(swConnection *conn);

#ifdef SW_USE_OPENSSL
int swSSL_init(char *cert_file, char *key_file);
void swSSL_free();
int swSSL_create(swConnection *conn, int flags);
int swSSL_accept(swConnection *conn);
void swSSL_close(swConnection *conn);
ssize_t swSSL_recv(swConnection *conn, void *__buf, size_t __n);
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
		return SSL_write(conn->ssl, __buf, __n);
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
