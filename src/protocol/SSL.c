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

#include "swoole.h"
#include "Connection.h"

#ifdef SW_USE_OPENSSL

static SSL_CTX *ssl_context = NULL;

int swSSL_init(char *cert_file, char *key_file)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ssl_context = SSL_CTX_new(SSLv23_method());
    if (ssl_context == NULL)
    {
        ERR_print_errors_fp(stderr);
        return SW_ERR;
    }

    SSL_CTX_set_options(ssl_context, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
    SSL_CTX_set_options(ssl_context, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);

    /*
     * set the local certificate from CertFile
     */
    if (SSL_CTX_use_certificate_file(ssl_context, cert_file, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return SW_ERR;
    }
    /*
     * set the private key from KeyFile (may be the same as CertFile)
     */
    if (SSL_CTX_use_PrivateKey_file(ssl_context, key_file, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return SW_ERR;
    }
    /*
     * verify private key
     */
    if (!SSL_CTX_check_private_key(ssl_context))
    {
        swWarn("Private key does not match the public certificate");
        return SW_ERR;
    }
    return SW_OK;
}

int swSSL_accept(swConnection *conn)
{
    int n = SSL_do_handshake(conn->ssl);
    if (n == 1)
    {
        conn->ssl_state = 1;
        if (conn->ssl->s3)
        {
            conn->ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
        }
        return SW_OK;
    }
    long err = SSL_get_error(conn->ssl, n);
    if (err == SSL_ERROR_WANT_READ)
    {
        return SW_OK;
    }
    else if (err == SSL_ERROR_WANT_WRITE)
    {
        return SW_OK;
    }
    swWarn("SSL_do_handshake() failed.");
    return SW_ERR;
}

void swSSL_close(swConnection *conn)
{
    SSL_free(conn->ssl);
}

ssize_t swSSL_recv(swConnection *conn, void *__buf, size_t __n)
{
    if (conn->ssl_state == 0 && swSSL_accept(conn) < 0)
    {
        //close connection
        return 0;
    }
    return SSL_read(conn->ssl, __buf, __n);
}

int swSSL_create(swConnection *conn, int flags)
{
    SSL *ssl = SSL_new(ssl_context);
    if (ssl == NULL)
    {
        swWarn("SSL_new() failed.");
        return SW_ERR;
    }
    if (!SSL_set_fd(ssl, conn->fd))
    {
        long err = ERR_get_error();
        swWarn("SSL_set_fd() failed. Error: %s[%ld]", ERR_reason_error_string(err), err);
        return SW_ERR;
    }
    if (flags & SW_SSL_CLIENT)
    {
        SSL_set_connect_state(ssl);
    }
    else
    {
        SSL_set_accept_state(ssl);
    }
    conn->ssl = ssl;
    conn->ssl_state = 0;
    return SW_OK;
}

void swSSL_free()
{
    if (ssl_context)
    {
        SSL_CTX_free(ssl_context);
    }
}

#endif
